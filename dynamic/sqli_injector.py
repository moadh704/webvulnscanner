# ── dynamic/sqli_injector.py ─────────────────────────────────────────────────

import time
import requests

import config

# ── Error-based detection strings ────────────────────────────────────────────
SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysqli_fetch",
    "supplied argument is not a valid mysql",
    "mysql_fetch_array",
    "division by zero",
    "odbc_exec",
    "pg_exec",
    "sqlite_query",
    "ora-01756",
    "unterminated string literal",
    "invalid query",
    "sql command not properly ended",
]

# ── Payload sets ─────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "\"",
    "1'",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
]

TIME_PAYLOADS = [
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(5000000,MD5(1))--",
]

BOOLEAN_PAYLOADS = [
    ("1' AND 1=1--", "1' AND 1=2--"),   # true / false pair
    ("1' OR 1=1--",  "1' OR 1=2--"),
]


class SQLiInjector:
    """
    Tests each endpoint parameter for SQL Injection using three techniques:
    - Error-based  : looks for database error strings in the response
    - Time-based   : measures response delay after injecting SLEEP()
    - Boolean-based: compares response size between true/false conditions
    """

    def __init__(self, session: requests.Session, scan_manager):
        self.session      = session
        self.scan_manager = scan_manager

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('sqli'):
            return []

        findings = []
        print("  [SQLi] Starting SQL Injection tests...")

        # Show what we're testing
        testable = [(ep, p) for ep in endpoints for p in ep['params']]
        print(f"  [SQLi] Testing {len(testable)} parameter(s) across "
              f"{len(endpoints)} endpoint(s)...")
        for ep, param in testable:
            print(f"  [SQLi] → {ep['method']} {ep['url']} param='{param}'")

        for ep in endpoints:
            for param in ep['params']:
                result = self._test_parameter(ep, param)
                if result:
                    findings.append(result)

        print(f"  [SQLi] Done. Found {len(findings)} SQLi finding(s).")
        return findings

    # ── Core testing logic ────────────────────────────────────────────────────

    def _test_parameter(self, ep: dict, param: str) -> dict:
        """Test a single parameter for SQLi. Returns a finding or None."""

        # 1. Error-based
        finding = self._test_error_based(ep, param)
        if finding:
            return finding

        # 2. Time-based
        finding = self._test_time_based(ep, param)
        if finding:
            return finding

        # 3. Boolean-based
        finding = self._test_boolean_based(ep, param)
        if finding:
            return finding

        return None

    def _test_error_based(self, ep: dict, param: str) -> dict:
        """Inject error-based payloads and check for DB error strings."""
        for payload in ERROR_PAYLOADS:
            response = self._send(ep, param, payload)
            if response is None:
                continue
            body = response.text.lower()
            for error in SQLI_ERRORS:
                if error in body:
                    print(f"  [SQLi] ✓ Error-based SQLi: {ep['url']} "
                          f"param='{param}' payload='{payload}'")
                    return self._make_finding(
                        ep       = ep,
                        param    = param,
                        payload  = payload,
                        method   = "error-based",
                        evidence = f"DB error string detected: '{error}'"
                    )
        return None

    def _test_time_based(self, ep: dict, param: str) -> dict:
        """Inject time-delay payloads and measure response time."""
        for payload in TIME_PAYLOADS:
            start    = time.time()
            response = self._send(ep, param, payload)
            elapsed  = time.time() - start

            if response is None:
                continue

            if elapsed >= config.TIME_BASED_DELAY:
                print(f"  [SQLi] ✓ Time-based SQLi: {ep['url']} "
                      f"param='{param}' delay={elapsed:.1f}s")
                return self._make_finding(
                    ep       = ep,
                    param    = param,
                    payload  = payload,
                    method   = "time-based",
                    evidence = f"Response delayed {elapsed:.1f}s "
                               f"(threshold: {config.TIME_BASED_DELAY}s)"
                )
        return None

    def _test_boolean_based(self, ep: dict, param: str) -> dict:
        """Compare responses for true/false boolean conditions."""
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            resp_true  = self._send(ep, param, true_payload)
            resp_false = self._send(ep, param, false_payload)

            if resp_true is None or resp_false is None:
                continue

            len_true  = len(resp_true.text)
            len_false = len(resp_false.text)

            if len_true == 0:
                continue

            diff = abs(len_true - len_false) / len_true

            if diff > 0.10:   # more than 10% difference
                print(f"  [SQLi] ✓ Boolean-based SQLi: {ep['url']} "
                      f"param='{param}' diff={diff:.0%}")
                return self._make_finding(
                    ep       = ep,
                    param    = param,
                    payload  = true_payload,
                    method   = "boolean-based",
                    evidence = f"Response size differs by {diff:.0%} "
                               f"between true/false conditions"
                )
        return None

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _send(self, ep: dict, param: str,
              payload: str) -> requests.Response:
        """Send a request with the payload injected into param."""
        params = dict(ep['params'])
        params[param] = payload

        # Strip URL fragment (#...) — not sent to server
        clean_url = ep['url'].split('#')[0]

        try:
            if ep['method'] == 'POST':
                return self.session.post(
                    clean_url, data=params,
                    timeout=config.REQUEST_TIMEOUT + config.TIME_BASED_DELAY,
                    allow_redirects=True
                )
            else:
                return self.session.get(
                    clean_url, params=params,
                    timeout=config.REQUEST_TIMEOUT + config.TIME_BASED_DELAY,
                    allow_redirects=True
                )
        except Exception:
            return None

    # ── Finding builder ───────────────────────────────────────────────────────

    def _make_finding(self, ep: dict, param: str, payload: str,
                      method: str, evidence: str) -> dict:
        return {
            'type'              : 'sqli',
            'owasp'             : 'A03:2021 - Injection',
            'url'               : ep['url'],
            'method'            : ep['method'],
            'parameter'         : param,
            'payload'           : payload,
            'technique'         : method,
            'evidence_dynamic'  : evidence,
            'evidence_static'   : None,
            'confidence'        : 0.65,    # Type 3 until correlated
            'module'            : 'dynamic',
            'finding_type'      : 3,
        }