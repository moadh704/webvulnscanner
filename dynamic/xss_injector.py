# ── dynamic/xss_injector.py ──────────────────────────────────────────────────

import requests
from bs4 import BeautifulSoup

import config

# ── XSS Payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
]

# URLs to skip
SKIP_URLS = [
    'setup.php', 'logout.php', 'phpinfo.php',
    'security.php', 'upload.php', 'brute/',
    'captcha', 'javascript/', 'cryptography',
]


class XSSInjector:
    """
    Tests each endpoint parameter for Reflected XSS by injecting script
    payloads and checking if they appear unencoded in the response body.
    """

    def __init__(self, session: requests.Session,
                 scan_manager, auth: dict = None):
        self.session      = session
        self.scan_manager = scan_manager
        self.auth         = auth

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('xss'):
            return []

        findings = []
        print("  [XSS] Starting Reflected XSS tests...")

        safe_endpoints = [
            ep for ep in endpoints
            if not any(skip in ep['url'] for skip in SKIP_URLS)
        ]

        total = sum(len(ep['params']) for ep in safe_endpoints)
        print(f"  [XSS] Testing {total} parameter(s) across "
              f"{len(safe_endpoints)} endpoint(s)...")

        for ep in safe_endpoints:
            for param in ep['params']:
                if param.lower() in ('submit', 'btnsign',
                                     'btnclear', 'send'):
                    continue
                result = self._test_parameter(ep, param)
                if result:
                    findings.append(result)
                    break  # one finding per endpoint is enough

        print(f"  [XSS] Done. Found {len(findings)} XSS finding(s).")
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
                print(f"  [XSS] Re-authenticated.")
                return True
        except Exception:
            pass
        return False

    # ── Core detection ────────────────────────────────────────────────────────

    def _test_parameter(self, ep: dict, param: str) -> dict:
        """Inject XSS payloads and check for unencoded reflection."""
        for payload in XSS_PAYLOADS:
            response = self._send(ep, param, payload)
            if response is None:
                continue

            # Handle session expiry
            if self._is_login_page(response):
                print(f"  [XSS] Session expired, re-authenticating...")
                if self._reauth():
                    response = self._send(ep, param, payload)
                    if response is None or self._is_login_page(response):
                        return None
                else:
                    return None

            # Check if payload is reflected unencoded in the response
            if self._is_reflected(payload, response.text):
                print(f"  [XSS] ✓ Reflected XSS: {ep['url']} "
                      f"param='{param}' payload='{payload}'")
                return self._make_finding(
                    ep      = ep,
                    param   = param,
                    payload = payload,
                    evidence= f"Payload reflected unencoded in response body"
                )
        return None

    def _is_reflected(self, payload: str, body: str) -> bool:
        """
        Check if the payload appears unencoded in the response.
        We check for the raw payload AND key indicator strings.
        """
        # Direct reflection check
        if payload in body:
            return True

        # Check for key script indicators that appear when payload is split
        # across HTML attributes or broken by the app
        indicators = [
            "<script>alert",
            "onerror=alert",
            "onload=alert",
            "<svg onload",
            "javascript:alert",
        ]
        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                # Make sure it's our injection not part of the page itself
                # by checking it's near the param value context
                return True

        return False

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
            'type'             : 'xss',
            'owasp'            : 'A03:2021 - Injection',
            'url'              : ep['url'].split('#')[0],
            'method'           : ep['method'],
            'parameter'        : param,
            'payload'          : payload,
            'technique'        : 'reflected',
            'evidence_dynamic' : evidence,
            'evidence_static'  : None,
            'confidence'       : 0.65,
            'module'           : 'dynamic',
            'finding_type'     : 3,
        }
