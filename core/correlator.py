# ── core/correlator.py ───────────────────────────────────────────────────────

import os

# ── CVSS base severity per vulnerability type ─────────────────────────────────
CVSS_BASE = {
    'sqli'     : 'High',
    'xss'      : 'Medium',
    'cmdi'     : 'Critical',
    'traversal': 'High',
    'idor'     : 'High',
    'headers'  : 'Medium',
}

# ── Severity levels for CVSS boost calculation ────────────────────────────────
SEVERITY_LEVELS = ['Low', 'Medium', 'High', 'Critical']

# ── Evidence priority for deduplication tie-breaking ─────────────────────────
TECHNIQUE_PRIORITY = {
    'error-based'         : 3,
    'output-based'        : 3,
    'reflected'           : 3,
    'path-traversal'      : 3,
    'sequential-enumeration': 3,
    'header-inspection'   : 3,
    'time-based'          : 2,
    'boolean-based'       : 1,
}


class Correlator:
    """
    Aggregates static and dynamic findings into a unified,
    deduplicated, typed, and severity-scored result set.

    Three-tier classification:
    - Type 1 (90%+): Static candidate confirmed by dynamic injection
    - Type 2 (40%) : Static only — not confirmed dynamically
    - Type 3 (65%) : Dynamic only — no static candidate

    CVSS severity boost:
    - Type 1: +2 severity levels
    - Type 3: +1 severity level
    - Type 2: no boost (forwarded to AI layer for review)
    """

    def correlate(self, all_findings: list) -> list:
        """
        Main entry point. Takes combined static + dynamic findings,
        returns correlated, deduplicated, scored result set.
        """
        print("  [Correlator] Correlating findings...")

        static_findings  = [f for f in all_findings
                            if f.get('module') == 'static']
        dynamic_findings = [f for f in all_findings
                            if f.get('module') == 'dynamic']

        print(f"  [Correlator] Input: {len(static_findings)} static, "
              f"{len(dynamic_findings)} dynamic findings.")

        # Step 1: Start with all dynamic findings (already have URL + param)
        result = {}

        for df in dynamic_findings:
            key = self._make_key(df)
            if key in result:
                # Keep finding with stronger evidence
                existing = result[key]
                if self._priority(df) > self._priority(existing):
                    result[key] = df
            else:
                result[key] = dict(df)

        # Step 2: Match static findings against dynamic findings
        upgraded_keys = set()  # track already-upgraded keys
        for sf in static_findings:
            matched = False
            for key, df in result.items():
                if self._static_matches_dynamic(sf, df):
                    if key not in upgraded_keys:
                        # First match — upgrade to Type 1
                        result[key]['finding_type']    = 1
                        result[key]['confidence']       = 0.90
                        result[key]['evidence_static']  = sf.get(
                            'evidence_static', '')
                        upgraded_keys.add(key)
                        print(f"  [Correlator] ↑ Type 1: "
                              f"{df['type']} at {df.get('url','')}")
                    matched = True
                    break

            if not matched:
                # Type 2 — static only, not confirmed dynamically
                if sf.get('file'):
                    sf_copy = dict(sf)
                    sf_copy['finding_type'] = 2
                    sf_copy['confidence']   = 0.40
                    if not sf_copy.get('url'):
                        sf_copy['url'] = sf_copy.get('file', 'unknown')
                    s_key = (f"static_{sf.get('file','')}_{sf.get('line',0)}"
                             f"_{sf.get('type','')}")
                    result[s_key] = sf_copy

        # Step 3: Apply CVSS severity boost
        final = []
        for finding in result.values():
            finding = self._apply_severity_boost(finding)
            final.append(finding)

        # Step 4: Sort by severity then confidence
        severity_order = {'Critical': 4, 'High': 3,
                          'Medium': 2, 'Low': 1}
        final.sort(
            key=lambda f: (
                severity_order.get(f.get('severity', 'Low'), 1),
                f.get('confidence', 0)
            ),
            reverse=True
        )

        # Summary
        t1 = sum(1 for f in final if f.get('finding_type') == 1)
        t2 = sum(1 for f in final if f.get('finding_type') == 2)
        t3 = sum(1 for f in final if f.get('finding_type') == 3)
        print(f"  [Correlator] Output: {len(final)} findings "
              f"(Type1={t1}, Type2={t2}, Type3={t3})")

        return final

    # ── Key generation ────────────────────────────────────────────────────────

    def _make_key(self, finding: dict) -> str:
        """
        Deduplication key: (vuln_type, url, parameter).
        Strips fragments and normalizes URL.
        """
        vuln_type = finding.get('type', 'unknown')
        url       = finding.get('url', '').split('#')[0].rstrip('/')
        param     = finding.get('parameter', '')
        return f"{vuln_type}|{url}|{param}"

    def _static_matches_dynamic(self, sf: dict, df: dict) -> bool:
        """
        Check if a static finding corresponds to a dynamic finding.
        Match on vulnerability type + URL path keyword from file path.
        """
        if sf.get('type') != df.get('type'):
            return False

        # Extract folder name from static file path
        # e.g. C:\xampp\htdocs\dvwa\vulnerabilities\sqli\index.php
        # → 'sqli'
        file_path = sf.get('file', '').replace('\\', '/')
        url       = df.get('url', '').lower()

        # Get the vulnerability folder name from the file path
        parts = file_path.lower().split('/')
        for part in parts:
            if part in url:
                return True

        # Also match by parameter name if available
        sf_param = sf.get('parameter', '')
        df_param = df.get('parameter', '')
        if sf_param and df_param and sf_param == df_param:
            return True

        return False

    # ── Severity boost ────────────────────────────────────────────────────────

    def _apply_severity_boost(self, finding: dict) -> dict:
        """Apply CVSS severity boost based on finding type."""
        vuln_type    = finding.get('type', 'unknown')
        finding_type = finding.get('finding_type', 3)

        base_severity = CVSS_BASE.get(vuln_type, 'Medium')
        base_idx      = SEVERITY_LEVELS.index(base_severity) \
                        if base_severity in SEVERITY_LEVELS else 1

        if finding_type == 1:
            boost = 2
        elif finding_type == 3:
            boost = 1
        else:
            boost = 0   # Type 2 — no boost

        final_idx            = min(base_idx + boost,
                                   len(SEVERITY_LEVELS) - 1)
        finding['severity']  = SEVERITY_LEVELS[final_idx]
        return finding

    # ── Priority helper ───────────────────────────────────────────────────────

    def _priority(self, finding: dict) -> int:
        """Return evidence priority score for tie-breaking."""
        technique = finding.get('technique', '')
        return TECHNIQUE_PRIORITY.get(technique, 0)