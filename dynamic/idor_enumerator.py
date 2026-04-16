# ── dynamic/idor_enumerator.py ───────────────────────────────────────────────

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import config

# URLs to skip
SKIP_URLS = [
    'setup.php', 'logout.php', 'phpinfo.php',
    'security.php', 'upload.php', 'brute/',
    'captcha', 'javascript/', 'cryptography',
    'instructions.php',
]


class IDOREnumerator:
    """
    Detects Insecure Direct Object References (IDOR) by:
    1. Finding integer parameters in URLs and form fields
    2. Incrementing/decrementing the value
    3. Comparing responses — if different content is returned
       for different IDs without authorization error, IDOR is confirmed
    """

    def __init__(self, session: requests.Session,
                 scan_manager, auth: dict = None):
        self.session      = session
        self.scan_manager = scan_manager
        self.auth         = auth

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('idor'):
            return []

        findings = []
        print("  [IDOR] Starting IDOR enumeration tests...")

        safe_endpoints = [
            ep for ep in endpoints
            if not any(skip in ep['url'] for skip in SKIP_URLS)
        ]

        print(f"  [IDOR] Scanning {len(safe_endpoints)} endpoint(s) "
              f"for integer parameters...")

        for ep in safe_endpoints:
            result = self._test_endpoint(ep)
            if result:
                findings.append(result)

        print(f"  [IDOR] Done. Found {len(findings)} IDOR finding(s).")
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
                print(f"  [IDOR] Re-authenticated.")
                return True
        except Exception:
            pass
        return False

    # ── Core detection ────────────────────────────────────────────────────────

    def _test_endpoint(self, ep: dict) -> dict:
        """
        Find integer parameters and test for IDOR by comparing
        responses for different ID values.
        """
        # Find integer-valued parameters
        integer_params = {
            k: v for k, v in ep['params'].items()
            if self._is_integer(v)
        }

        if not integer_params:
            return None

        for param, value in integer_params.items():
            result = self._test_integer_param(ep, param, int(value))
            if result:
                return result

        return None

    def _test_integer_param(self, ep: dict, param: str,
                             base_id: int) -> dict:
        """
        Test an integer parameter for IDOR by trying adjacent IDs.
        """
        clean_url = ep['url'].split('#')[0]

        # Get baseline response with original ID
        baseline = self._send(ep, param, str(base_id))
        if baseline is None or self._is_login_page(baseline):
            return None

        # Skip if baseline returns auth error
        if baseline.status_code in (401, 403):
            return None

        baseline_len = len(baseline.text)

        # Try adjacent IDs
        test_ids = []
        if base_id > 1:
            test_ids.append(base_id - 1)
        test_ids.append(base_id + 1)
        test_ids.append(base_id + 2)

        for test_id in test_ids:
            response = self._send(ep, param, str(test_id))
            if response is None:
                continue

            if self._is_login_page(response):
                if self._reauth():
                    response = self._send(ep, param, str(test_id))
                    if response is None or self._is_login_page(response):
                        continue
                else:
                    continue

            # IDOR confirmed if:
            # 1. Response is 200 (not 401/403/404)
            # 2. Response content is different from baseline
            #    (meaning different user data was returned)
            # 3. Response is not empty
            if response.status_code == 200 and \
               len(response.text) > 100 and \
               self._content_differs(baseline.text, response.text):

                print(f"  [IDOR] ✓ IDOR detected: {clean_url} "
                      f"param='{param}' "
                      f"id={base_id} → id={test_id} returns different content")
                return self._make_finding(
                    ep       = ep,
                    param    = param,
                    base_id  = base_id,
                    test_id  = test_id,
                    evidence = (
                        f"ID {base_id} returns {baseline_len} bytes, "
                        f"ID {test_id} returns {len(response.text)} bytes — "
                        f"different user-specific content accessible "
                        f"without authorization check"
                    )
                )

        return None

    def _content_differs(self, text1: str, text2: str) -> bool:
        """
        Check if two responses contain meaningfully different content.
        Ignores minor differences like timestamps or CSRF tokens.
        """
        # Remove common dynamic elements before comparing
        def normalize(text):
            # Remove CSRF tokens
            text = re.sub(r'user_token["\s]*value="[^"]*"', '', text)
            # Remove session IDs
            text = re.sub(r'PHPSESSID=[a-z0-9]+', '', text)
            # Remove timestamps
            text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
            return text.strip()

        t1 = normalize(text1)
        t2 = normalize(text2)

        if len(t1) == 0:
            return False

        # Calculate difference ratio
        diff = abs(len(t1) - len(t2)) / len(t1)
        return diff > 0.05   # more than 5% difference

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_integer(self, value: str) -> bool:
        """Check if a string value looks like an integer ID."""
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            return False

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
              value: str) -> requests.Response:
        clean_url = ep['url'].split('#')[0]
        params    = dict(ep['params'])
        params[param] = value

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
                      base_id, test_id, evidence) -> dict:
        return {
            'type'             : 'idor',
            'owasp'            : 'A01:2021 - Broken Access Control',
            'url'              : ep['url'].split('#')[0],
            'method'           : ep['method'],
            'parameter'        : param,
            'payload'          : str(test_id),
            'technique'        : 'sequential-enumeration',
            'evidence_dynamic' : evidence,
            'evidence_static'  : None,
            'confidence'       : 0.65,
            'module'           : 'dynamic',
            'finding_type'     : 3,
        }