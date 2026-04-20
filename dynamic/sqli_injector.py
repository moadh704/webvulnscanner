# ── dynamic/sqli_injector.py ─────────────────────────────────────────────────

import time
import requests
from bs4 import BeautifulSoup

import config

# ── Error strings that indicate a SQL error in the response ──────────────────
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
    "unterminated string literal",
    "invalid query",
    "sql command not properly ended",
    "mysql_num_rows",
    "mysql_result",
    "error in your sql",
]

# ── Payloads ──────────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "\"",
    "1'",
    "' OR '1'='1",
    "' OR 1=1--",
    "1' OR '1'='1'--",
]

TIME_PAYLOADS = [
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
]

BOOLEAN_PAYLOADS = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1' OR 1=1--",  "1' OR 1=2--"),
]

# URLs to skip — destructive or session-breaking pages
SKIP_URLS = [
    'setup.php', 'logout.php', 'phpinfo.php',
    'security.php', 'upload.php', 'brute/',
    'captcha', 'javascript/', 'cryptography',
    'instructions.php',
]


class SQLiInjector:
    """
    Tests each endpoint parameter for SQL Injection:
    - Error-based  : looks for DB error strings in the response
    - Time-based   : measures response delay after SLEEP() payload
    - Boolean-based: compares response size between true/false conditions
    """

    def __init__(self, session: requests.Session,
                 scan_manager, auth: dict = None):
        self.session      = session
        self.scan_manager = scan_manager
        self.auth         = auth

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('sqli'):
            return []

        findings = []
        print("  [SQLi] Starting SQL Injection tests...")

        safe_endpoints = [
            ep for ep in endpoints
            if not any(skip in ep['url'] for skip in SKIP_URLS)
        ]

        total_params = sum(len(ep['params']) for ep in safe_endpoints)
        print(f"  [SQLi] Testing {total_params} parameter(s) across "
              f"{len(safe_endpoints)} endpoint(s)...")

        for ep in safe_endpoints:
            for param in ep['params']:
                # Skip submit buttons
                if param.lower() in ('submit', 'btnSign', 'btnClear', 'send'):
                    continue
                result = self._test_parameter(ep, param)
                if result:
                    findings.append(result)
                    break   # one finding per endpoint is enough

        print(f"  [SQLi] Done. Found {len(findings)} SQLi finding(s).")
        return findings

    # ── Re-authentication ─────────────────────────────────────────────────────

    def _reauth(self):
        """Re-login if session has expired."""
        if not self.auth:
            return False
        try:
            login_url = self.auth['url']
            resp      = self.session.get(
                login_url, timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
            soup      = BeautifulSoup(resp.text, 'html.parser')
            post_data = {}
            for h in soup.find_all('input', type='hidden'):
                if h.get('name'):
                    post_data[h['name']] = h.get('value', '')
            post_data[self.auth['username_field']] = self.auth['username']
            post_data[self.auth['password_field']] = self.auth['password']
            for k, v in self.auth.get('extra_fields', {}).items():
                post_data[k] = v
            r = self.session.post(
                login_url, data=post_data,
                timeout=config.REQUEST_TIMEOUT, allow_redirects=True
            )
            if 'login' not in r.url.lower():
                print(f"  [SQLi] Re-authenticated.")
                return True
        except Exception as e:
            print(f"  [SQLi] Re-auth failed: {e}")
        return False

    # ── Core testing logic ────────────────────────────────────────────────────

    def _test_parameter(self, ep: dict, param: str) -> dict:
        finding = self._test_error_based(ep, param)
        if finding:
            return finding
        finding = self._test_time_based(ep, param)
        if finding:
            return finding
        finding = self._test_boolean_based(ep, param)
        return finding

    def _test_error_based(self, ep: dict, param: str) -> dict:
        for payload in ERROR_PAYLOADS:
            response = self._send(ep, param, payload)
            if response is None:
                continue

            # Detect session expiry — re-auth and retry once
            if self._is_login_page(response):
                print(f"  [SQLi] Session expired, re-authenticating...")
                if self._reauth():
                    response = self._send(ep, param, payload)
                    if response is None or self._is_login_page(response):
                        return None
                else:
                    return None

            body = response.text.lower()
            for error in SQLI_ERRORS:
                if error in body:
                    print(f"  [SQLi] ✓ Error-based: {ep['url']} "
                          f"param='{param}' payload='{payload}'")
                    return self._make_finding(
                        ep, param, payload, "error-based",
                        f"DB error: '{error}'"
                    )
        return None

    def _test_time_based(self, ep: dict, param: str) -> dict:
        for payload in TIME_PAYLOADS:
            start    = time.time()
            response = self._send(ep, param, payload)
            elapsed  = time.time() - start
            if response is None:
                continue
            if self._is_login_page(response):
                if self._reauth():
                    continue
                return None
            if elapsed >= config.TIME_BASED_DELAY:
                print(f"  [SQLi] ✓ Time-based: {ep['url']} "
                      f"param='{param}' delay={elapsed:.1f}s")
                return self._make_finding(
                    ep, param, payload, "time-based",
                    f"Response delayed {elapsed:.1f}s"
                )
        return None

    def _test_boolean_based(self, ep: dict, param: str) -> dict:
        for true_p, false_p in BOOLEAN_PAYLOADS:
            r_true  = self._send(ep, param, true_p)
            r_false = self._send(ep, param, false_p)
            if r_true is None or r_false is None:
                continue
            if self._is_login_page(r_true) or self._is_login_page(r_false):
                if self._reauth():
                    continue
                return None
            len_t = len(r_true.text)
            len_f = len(r_false.text)
            if len_t == 0:
                continue
            diff = abs(len_t - len_f) / len_t
            if diff > 0.10:
                print(f"  [SQLi] ✓ Boolean-based: {ep['url']} "
                      f"param='{param}' diff={diff:.0%}")
                return self._make_finding(
                    ep, param, true_p, "boolean-based",
                    f"Response size differs {diff:.0%} true vs false"
                )
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_login_page(self, response) -> bool:
        """Return True if the response is the login page."""
        if response is None:
            return False
        if 'login' in response.url.lower():
            return True
        if 'login.css' in response.text.lower():
            return True
        return False

    def _get_user_token(self, url: str) -> str:
        """Fetch fresh CSRF token from page."""
        try:
            resp  = self.session.get(
                url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True
            )
            soup  = BeautifulSoup(resp.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            return token['value'] if token else ''
        except Exception:
            return ''

    def _send(self, ep: dict, param: str,
              payload: str) -> requests.Response:
        """Send injection request — follows redirects, checks final URL."""
        clean_url = ep['url'].split('#')[0]
        params    = dict(ep['params'])
        params[param] = payload

        # Refresh CSRF token if needed
        if 'user_token' in params:
            params['user_token'] = self._get_user_token(clean_url)

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

    def _make_finding(self, ep, param, payload,
                      method, evidence) -> dict:
        return {
            'type'             : 'sqli',
            'owasp'            : 'A03:2025 - Injection',
            'url'              : ep['url'].split('#')[0],
            'method'           : ep['method'],
            'parameter'        : param,
            'payload'          : payload,
            'technique'        : method,
            'evidence_dynamic' : evidence,
            'evidence_static'  : None,
            'confidence'       : 0.65,
            'module'           : 'dynamic',
            'finding_type'     : 3,
        }
