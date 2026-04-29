# ── dynamic/xss_injector.py ──────────────────────────────────────────────────

import html
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
    payloads and checking if they appear UNENCODED in the response body.

    A reflection is considered exploitable only when the special
    characters of the payload (<, >, ", ') survive the round-trip to the
    server intact. If the application HTML-encodes the payload before
    reflecting it (e.g. '&lt;script&gt;alert(1)&lt;/script&gt;'), the
    finding is rejected — the payload may appear as text but cannot
    execute as script.
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
                    evidence= "Payload reflected unencoded in response body "
                              "(special characters intact)"
                )
        return None

    def _is_reflected(self, payload: str, body: str) -> bool:
        """
        Determine whether the payload was reflected in an exploitable form.

        The check is two-step:

        1. The raw payload must appear in the body — every byte intact.
           If the body only contains an HTML-encoded variant of the
           payload (e.g. '&lt;script&gt;') it is NOT exploitable, so we
           never reach step 2 for that case.

        2. The structurally-significant characters of the payload must
           also appear in the body in their literal form. This guards
           against partial reflection where the application strips the
           tag delimiters but echoes the rest of the string.

        Examples:
          payload  = '<script>alert(1)</script>'
          body 1   = '... <script>alert(1)</script> ...'    -> True  (vulnerable)
          body 2   = '... &lt;script&gt;alert(1)&lt;/script&gt; ...'
                                                            -> False (escaped)
          body 3   = '... script alert 1 script ...'        -> False (stripped)
        """
        if not payload or not body:
            return False

        # Step 1: raw payload present?
        if payload not in body:
            return False

        # Step 2: structural characters intact?
        # The payload uses these characters to break out of context. If any
        # of them are present in the payload, at least one literal copy must
        # also appear in the body for the reflection to be exploitable.
        structural_chars = ['<', '>', '"', "'"]
        for ch in structural_chars:
            if ch in payload and ch not in body:
                return False

        # Step 3: defence against the edge case where the application
        # echoes BOTH the raw payload AND its encoded form (e.g. once in
        # an error log and once as escaped HTML in the page). If the
        # encoded version dominates, reject.
        encoded = html.escape(payload, quote=True)
        if encoded != payload:
            # If the encoded variant is in the body but the raw payload
            # appears fewer times than the encoded variant, the payload
            # was almost certainly properly escaped and the raw match is
            # incidental (e.g. inside a <textarea> echo of the input).
            if encoded in body:
                if body.count(encoded) >= body.count(payload):
                    return False

        return True

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
            'owasp'            : 'A03:2025 - Injection',
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