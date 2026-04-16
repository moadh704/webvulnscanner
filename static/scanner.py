# ── static/scanner.py ────────────────────────────────────────────────────────

import os
import json
import subprocess

import config


# Map rule IDs to internal vulnerability types
VULN_TYPE_MAP = {
    'sqli'      : 'sqli',
    'xss'       : 'xss',
    'cmdi'      : 'cmdi',
    'traversal' : 'traversal',
}

# CVSS base severity per vulnerability type
SEVERITY_MAP = {
    'sqli'      : 'High',
    'xss'       : 'Medium',
    'cmdi'      : 'Critical',
    'traversal' : 'High',
}


class StaticScanner:
    """
    Runs Semgrep with custom YAML rules against the target source directory.
    Produces candidate findings normalized into the unified Finding schema.
    Output is passed directly to the dynamic module for confirmation.
    """

    def __init__(self, scan_manager):
        self.scan_manager = scan_manager
        self.rules_dir    = os.path.join(
            os.path.dirname(__file__), 'rules'
        )

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, source_dir: str) -> list:
        """
        Run Semgrep on source_dir using active module rules.
        Returns normalized findings list.
        """
        print(f"  [Static] Starting AST-based analysis on: {source_dir}")

        if not os.path.isdir(source_dir):
            print(f"  [Static] Source directory not found: {source_dir}")
            return []

        # Build list of rule files for active modules only
        rule_files = self._get_active_rule_files()
        if not rule_files:
            print(f"  [Static] No active rule files found.")
            return []

        print(f"  [Static] Running rules: "
              f"{[os.path.basename(r) for r in rule_files]}")

        # Run Semgrep
        raw_results = self._run_semgrep(source_dir, rule_files)
        if raw_results is None:
            return []

        # Normalize results
        findings = self._normalize(raw_results)
        print(f"  [Static] Done. Found {len(findings)} "
              f"candidate finding(s).")
        return findings

    # ── Semgrep execution ─────────────────────────────────────────────────────

    def _get_active_rule_files(self) -> list:
        """Return rule file paths for currently active modules."""
        rule_files = []
        for module in ['sqli', 'xss', 'cmdi', 'traversal']:
            if self.scan_manager.is_active(module):
                rule_path = os.path.join(self.rules_dir, f"{module}.yaml")
                if os.path.exists(rule_path):
                    rule_files.append(rule_path)
        return rule_files

    def _run_semgrep(self, source_dir: str,
                     rule_files: list) -> list:
        """Execute Semgrep and return raw findings list."""
        # Build command
        cmd = [
            'semgrep',
            '--json',
            '--no-rewrite-rule-ids',
            '--quiet',
        ]

        # Add each rule file
        for rule_file in rule_files:
            cmd.extend(['--config', rule_file])

        # Add target directory
        cmd.append(source_dir)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode not in (0, 1):
                # returncode 1 means findings were found — that's normal
                # other codes indicate errors
                print(f"  [Static] Semgrep error: {result.stderr[:200]}")
                return []

            output = json.loads(result.stdout)
            return output.get('results', [])

        except subprocess.TimeoutExpired:
            print(f"  [Static] Semgrep timed out after 120 seconds.")
            return []
        except json.JSONDecodeError:
            print(f"  [Static] Could not parse Semgrep output.")
            return []
        except FileNotFoundError:
            print(f"  [Static] Semgrep not found. "
                  f"Install with: pip install semgrep")
            return []
        except Exception as e:
            print(f"  [Static] Semgrep execution failed: {e}")
            return []

    # ── Normalization ─────────────────────────────────────────────────────────

    def _normalize(self, raw_results: list) -> list:
        """
        Normalize Semgrep results into the unified Finding schema.
        All static findings start at confidence 0.40 (Type 2 — unconfirmed).
        They will be upgraded to Type 1 (0.90+) if confirmed dynamically.
        """
        findings = []
        seen     = set()   # deduplicate by (file, line, vuln_type)

        for r in raw_results:
            try:
                check_id   = r.get('check_id', '')
                vuln_type  = self._map_vuln_type(check_id)
                file_path  = r.get('path', '')
                line       = r.get('start', {}).get('line', 0)
                code       = r.get('extra', {}).get('lines', '').strip()
                message    = r.get('extra', {}).get('message', '')
                metadata   = r.get('extra', {}).get('metadata', {})
                owasp      = metadata.get('owasp',
                                          'A03:2021 - Injection')

                # Skip if module not active
                if not self.scan_manager.is_active(vuln_type):
                    continue

                # Deduplicate
                key = (file_path, line, vuln_type)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    'type'             : vuln_type,
                    'owasp'            : owasp,
                    'file'             : file_path,
                    'line'             : line,
                    'code'             : code,
                    'message'          : message,
                    'url'              : None,   # filled by correlator
                    'parameter'        : None,   # filled by correlator
                    'evidence_static'  : f"File: {file_path}, "
                                         f"Line: {line}, "
                                         f"Code: {code}",
                    'evidence_dynamic' : None,
                    'confidence'       : 0.40,   # awaits dynamic confirmation
                    'severity'         : SEVERITY_MAP.get(vuln_type,
                                                           'Medium'),
                    'module'           : 'static',
                    'finding_type'     : 2,       # unconfirmed until dynamic
                })

            except Exception:
                continue

        return findings

    def _map_vuln_type(self, check_id: str) -> str:
        """Map Semgrep rule ID to internal vulnerability type."""
        check_id_lower = check_id.lower()
        for key, vuln_type in VULN_TYPE_MAP.items():
            if key in check_id_lower:
                return vuln_type
        return 'unknown'
