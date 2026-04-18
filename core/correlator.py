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

        # Step 2: For each dynamic finding, find the BEST matching static finding
        for key, df in result.items():
            best_sf    = None
            best_score = 0

            for sf in static_findings:
                score = self._match_score(sf, df)
                if score > best_score:
                    best_score = score
                    best_sf    = sf

            if best_sf and best_score > 0:
                # Upgrade to Type 1
                result[key]['finding_type']   = 1
                result[key]['confidence']      = 0.90
                result[key]['evidence_static'] = best_sf.get(
                    'evidence_static', '')
                print(f"  [Correlator] ↑ Type 1: "
                      f"{df['type']} at {df.get('url','')} "
                      f"(matched: {best_sf.get('file','').split(chr(92))[-1]})")

        # Step 3: Add unmatched static findings as Type 2
        for sf in static_findings:
            # Check if this static finding was used to upgrade a dynamic one
            matched = False
            for key, df in result.items():
                if df.get('finding_type') == 1 and \
                   df.get('evidence_static') == sf.get('evidence_static'):
                    matched = True
                    break
            if not matched and sf.get('file'):
                sf_copy = dict(sf)
                sf_copy['finding_type'] = 2
                sf_copy['confidence']   = 0.40
                if not sf_copy.get('url'):
                    sf_copy['url'] = sf_copy.get('file', 'unknown')
                s_key = (f"static_{sf.get('file','')}_{sf.get('line',0)}"
                         f"_{sf.get('type','')}")
                if s_key not in result:
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

    def _match_score(self, sf: dict, df: dict) -> int:
        """
        Return a numeric match score between a static and dynamic finding.
        Higher score = better match. 0 = no match.
        """
        if sf.get('type') != df.get('type'):
            return 0

        file_path = sf.get('file', '').replace('\\', '/').lower()
        url       = df.get('url', '').lower()

        SKIP_SEGMENTS = {
            'index', 'login', 'logout', 'home', 'main',
            'app', 'src', 'lib', 'includes', 'config',
            'htdocs', 'www', 'public', 'html', 'php',
            'xampp', 'users', 'dell', 'desktop',
        }

        file_parts = [
            p for p in file_path.split('/')
            if p and len(p) > 2
            and p not in SKIP_SEGMENTS
            and not p.endswith('.php')
            and not p.endswith('.py')
        ]

        from urllib.parse import urlparse
        url_path  = urlparse(url).path.lower()
        url_parts = [p for p in url_path.split('/') if p and len(p) > 2]

        # Count overlapping meaningful segments
        score = sum(1 for part in file_parts if part in url_parts)
        return score

    def _static_matches_dynamic(self, sf: dict, df: dict) -> bool:
        """Convenience wrapper — returns True if score > 0."""
        return self._match_score(sf, df) > 0

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