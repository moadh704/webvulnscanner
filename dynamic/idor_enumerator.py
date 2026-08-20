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

        # Test common REST API patterns for potential IDOR vulnerabilities
        base_url = self._get_base_url_from_config()
        if self._looks_like_modern_web_app(base_url):
            print("  [IDOR] Testing common REST API endpoints for ID enumeration...")
            api_findings = self._enumerate_ids_in_common_apis(base_url)
            findings.extend(api_findings)

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

    def _get_base_url_from_config(self) -> str:
        try:
            return config.TARGET_URL
        except Exception:
            return None

    def _looks_like_modern_web_app(self, url: str) -> bool:
        """
        Detect modern web applications that commonly expose REST APIs 
        (frequent source of IDOR vulnerabilities).
        """
        if not url:
            return False

        url_lower = url.lower()
        modern_ports = ['3000', '8000', '8080', '5000', '4200', '3001']
        api_indicators = ['/api/', '/rest/', 'api.', 'graphql']

        if any(port in url_lower for port in modern_ports):
            return True
        if any(indicator in url_lower for indicator in api_indicators):
            return True
        return False

    def _enumerate_ids_in_common_apis(self, base_url: str) -> list:
        """Test common REST API endpoints for potential IDOR vulnerabilities."""
        findings = []
        base = base_url.rstrip('/')

        # Common REST API endpoint patterns that often have integer IDs
        # (frequent source of IDOR vulnerabilities in modern web apps)
        api_endpoints = [
            '/api/users',
            '/api/products',
            '/api/orders',
            '/api/items',
            '/rest/users',
            '/rest/products',
            '/api/v1/users',
            '/api/v1/products',
        ]

        for endpoint in api_endpoints:
            url = f"{base}{endpoint}"
            try:
                resp = self.session.get(
                    url, timeout=config.REQUEST_TIMEOUT,
                    allow_redirects=True
                )
                if resp.status_code == 200:
                    # Try enumerating IDs
                    for id_val in [1, 2, 3]:
                        id_url = f"{url}/{id_val}"
                        r1 = self.session.get(
                            id_url, timeout=config.REQUEST_TIMEOUT
                        )
                        r2 = self.session.get(
                            f"{url}/{id_val + 1}",
                            timeout=config.REQUEST_TIMEOUT
                        )
                        if r1.status_code == 200 and \
                           r2.status_code == 200 and \
                           len(r1.text) > 50 and \
                           r1.text != r2.text:
                            print(f"  [IDOR] ✓ IDOR detected: {id_url} "
                                  f"returns different content for "
                                  f"id={id_val} vs id={id_val + 1}")
                            findings.append({
                                'type'            : 'idor',
                                'owasp'           : 'A01:2025 - Broken Access Control',
                                'url'             : id_url,
                                'method'          : 'GET',
                                'parameter'       : 'id',
                                'payload'         : str(id_val),
                                'technique'       : 'sequential-enumeration',
                                'evidence_dynamic': (
                                    f"REST API endpoint {endpoint}/{{id}} "
                                    f"returns different user-specific content "
                                    f"for different IDs without authorization check"
                                ),
                                'evidence_static' : None,
                                'confidence'      : 0.65,
                                'module'          : 'dynamic',
                                'finding_type'    : 3,
                            })
                            break
            except Exception:
                continue

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

        # Control: refetch the SAME id. If the page already changes
        # between identical requests (timestamps, tokens, random
        # banners), any "different content" signal is untrustworthy —
        # skip the parameter honestly instead of reporting an IDOR.
        control = self._send(ep, param, str(base_id))
        control_noise = 0.0
        if control is not None and control.status_code == \
                baseline.status_code:
            control_noise = self._diff_ratio(baseline.text, control.text)
        if control_noise > 0.30:
            print(f"  [IDOR] Skipping {clean_url} param='{param}': "
                  f"page too dynamic (same-ID noise {control_noise:.0%})")
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
            # 2. Response is not empty
            # 3. Content differs from baseline by MORE than the
            #    same-ID control noise (plus a small margin)
            if response.status_code == 200 and \
               len(response.text) > 100:
                diff = self._diff_ratio(baseline.text, response.text)
                if diff > 0.05 and diff > control_noise + 0.05:
                    print(f"  [IDOR] ✓ IDOR detected: {clean_url} "
                          f"param='{param}' "
                          f"id={base_id} → id={test_id} "
                          f"(diff {diff:.0%} vs noise {control_noise:.0%})")
                    return self._make_finding(
                        ep       = ep,
                        param    = param,
                        base_id  = base_id,
                        test_id  = test_id,
                        evidence = (
                            f"ID {base_id} returns {baseline_len} bytes, "
                            f"ID {test_id} returns "
                            f"{len(response.text)} bytes — different "
                            f"user-specific content accessible without "
                            f"authorization check"
                        )
                    )

        return None

    def _diff_ratio(self, text1: str, text2: str) -> float:
        """
        Content dissimilarity between two responses, 0.0 (identical)
        to 1.0 (completely different).

        Strips volatile elements (CSRF tokens, session IDs, dates,
        hidden form fields), then compares the sets of content words
        (Jaccard dissimilarity). Word-level comparison detects
        different data even when page length and layout are identical
        (e.g. "User: Alice" vs "User: Bob").
        """
        def normalize(text):
            # Remove CSRF tokens
            text = re.sub(r'user_token["\s]*value="[^"]*"', '', text)
            # Remove session IDs
            text = re.sub(r'PHPSESSID=[a-z0-9]+', '', text)
            # Remove timestamps and dates
            text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
            # Remove hidden form fields (values are often dynamic)
            text = re.sub(r'<input[^>]*type=["\']hidden["\'][^>]*>',
                          '', text, flags=re.IGNORECASE)
            return text.strip()

        n1 = normalize(text1)
        n2 = normalize(text2)

        if not n1 or not n2:
            return 1.0 if bool(n1) != bool(n2) else 0.0

        words1 = set(re.findall(r'[a-z0-9]+', n1.lower()))
        words2 = set(re.findall(r'[a-z0-9]+', n2.lower()))

        if not words1 or not words2:
            return abs(len(n1) - len(n2)) / max(len(n1), 1)

        union = len(words1 | words2)
        if union == 0:
            return 0.0
        return 1.0 - (len(words1 & words2) / union)

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
            'owasp'            : 'A01:2025 - Broken Access Control',
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
