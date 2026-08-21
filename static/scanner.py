# ── static/scanner.py ─────────────────────────────────────────────────

import os
import json
import shutil
import subprocess
import sys

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
        self._semgrep_cmd = None   # resolved lazily by _resolve_semgrep()

    # ── Public entry point ─────────────────────────────────────────────────────────────

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

    # ── Semgrep execution ─────────────────────────────────────────────────────────────

    def _get_active_rule_files(self) -> list:
        """Return rule file paths for currently active modules."""
        rule_files = []
        for module in ['sqli', 'xss', 'cmdi', 'traversal']:
            if self.scan_manager.is_active(module):
                rule_path = os.path.join(self.rules_dir, f"{module}.yaml")
                if os.path.exists(rule_path):
                    rule_files.append(rule_path)
        return rule_files

    def _resolve_semgrep(self) -> list:
        """
        Find a working way to invoke Semgrep.
        Probes candidates in order and caches the first that responds
        to --version. Handles installs where the Scripts dir is not on
        PATH (Windows user-site installs) and broken console wrappers.
        """
        if self._semgrep_cmd is not None:
            return self._semgrep_cmd

        candidates = []

        def _add_script_dir(base_dir):
            if not base_dir:
                return
            for name in ('semgrep', 'pysemgrep'):
                exe = os.path.join(base_dir, 'Scripts',
                                   name + ('.exe' if os.name == 'nt'
                                           else ''))
                if os.path.isfile(exe):
                    candidates.append([exe])

        # 1. On PATH (normal installs)
        for name in ('semgrep', 'pysemgrep'):
            exe = shutil.which(name)
            if exe:
                candidates.append([exe])

        # 2. Scripts dir next to the running interpreter
        _add_script_dir(os.path.dirname(sys.executable))

        # 3. User-site Scripts dir (pip install --user on Windows)
        try:
            import site
            _add_script_dir(os.path.dirname(site.USER_SITE))
        except Exception:
            pass

        # 4. python -m semgrep as last resort (deprecated but may work)
        candidates.append([sys.executable, '-m', 'semgrep'])

        seen = set()
        for cmd in candidates:
            key = tuple(cmd)
            if key in seen:
                continue
            seen.add(key)
            try:
                probe = subprocess.run(
                    cmd + ['--version'],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    encoding='utf-8',
                    errors='replace',
                )
                if probe.returncode == 0 and (probe.stdout or probe.stderr):
                    self._semgrep_cmd = cmd
                    return cmd
            except (OSError, subprocess.TimeoutExpired):
                continue

        return []

    def _run_semgrep(self, source_dir: str,
                     rule_files: list) -> list:
        """Execute Semgrep and return raw findings list."""
        # Resolve a working Semgrep invocation
        semgrep = self._resolve_semgrep()
        if not semgrep:
            print(f"  [Static] Semgrep not found. "
                  f"Install with: pip install semgrep")
            return []

        # Build command
        cmd = list(semgrep) + [
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
                timeout=120,
                encoding='utf-8',
                errors='replace',
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
        except Exception as e:
            print(f"  [Static] Semgrep execution failed: {e}")
            return []

    # ── Normalization ─────────────────────────────────────────────────────────────────

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
                end_line   = r.get('end', {}).get('line', line)
                # `extra.lines` from Semgrep is unreliable (some builds
                # return a "requires login" placeholder instead of the
                # matched code). Read the matched region straight from
                # the source file — the reported line numbers ARE correct.
                code       = self._read_matched_code(file_path, line,
                                                     end_line)
                message    = r.get('extra', {}).get('message', '').strip()
                metadata   = r.get('extra', {}).get('metadata', {})
                owasp      = metadata.get('owasp',
                                          'A05:2025 - Injection')

                # Skip if module not active
                if not self.scan_manager.is_active(vuln_type):
                    continue

                # Deduplicate
                key = (file_path, line, vuln_type)
                if key in seen:
                    continue
                seen.add(key)

                # Build informative evidence string for the AI reviewer.
                # Includes the rule's own explanation (message) and the
                # actual matched code line, so the AI has real context
                # rather than just a file path.
                evidence = (
                    f"File: {file_path}, Line: {line}\n"
                    f"Rule: {check_id}\n"
                    f"Pattern: {message}\n"
                    f"Code context:\n{code}"
                )

                findings.append({
                    'type'             : vuln_type,
                    'owasp'            : owasp,
                    'file'             : file_path,
                    'line'             : line,
                    'code'             : code,
                    'message'          : message,
                    'url'              : None,   # filled by correlator
                    'parameter'        : None,   # filled by correlator
                    'evidence_static'  : evidence,
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

    def _read_matched_code(self, file_path: str, start_line: int,
                           end_line: int, context: int = 8) -> str:
        """
        Read the matched source region straight from the target file,
        with surrounding context so sanitization before/after the match
        is visible to the AI reviewer.

        Semgrep's `extra.lines` field is unreliable (some community
        builds return a "requires login" watermark instead of the
        matched code), while the reported start/end line numbers are
        accurate. Falls back to a window around the match line if the
        match region is empty, and never returns the watermark.
        """
        try:
            with open(file_path, 'r',
                      encoding='utf-8', errors='replace') as f:
                src_lines = f.read().splitlines()
        except OSError:
            return "(unreadable source file)"
        if not src_lines:
            return "(empty source file)"
        total = len(src_lines)
        # Expand the match region by `context` lines on both sides so
        # the reviewer can see escaping/validation applied downstream.
        start = max(start_line - 1 - context, 0)
        end   = min(end_line + context, total)
        matched = "\n".join(src_lines[start:end]).strip()
        if matched:
            return matched
        # Match spans an empty region (e.g. EOF) — show the closest line.
        idx = min(max(start_line - 1, 0), total - 1)
        return src_lines[idx].strip() or "(no matched code)"

    def _map_vuln_type(self, check_id: str) -> str:
        """Map Semgrep rule ID to internal vulnerability type."""
        check_id_lower = check_id.lower()
        for key, vuln_type in VULN_TYPE_MAP.items():
            if key in check_id_lower:
                return vuln_type
        return 'unknown'