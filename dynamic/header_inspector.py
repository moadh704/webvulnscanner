# ── dynamic/header_inspector.py ──────────────────────────────────────────────

import requests
from bs4 import BeautifulSoup

import config

# ── Security headers and their risk if missing ────────────────────────────────
SECURITY_HEADERS = {
    'X-Frame-Options': {
        'risk'       : 'Clickjacking attacks — page can be embedded in iframes',
        'severity'   : 'Medium',
    },
    'Content-Security-Policy': {
        'risk'       : 'No XSS mitigation policy — scripts from any source allowed',
        'severity'   : 'High',
    },
    'Strict-Transport-Security': {
        'risk'       : 'HTTP downgrade attacks — HTTPS not enforced',
        'severity'   : 'Medium',
    },
    'X-Content-Type-Options': {
        'risk'       : 'MIME-type sniffing — browser may misinterpret content',
        'severity'   : 'Low',
    },
    'Referrer-Policy': {
        'risk'       : 'URL data leaked to third parties via Referer header',
        'severity'   : 'Low',
    },
    'Permissions-Policy': {
        'risk'       : 'No browser feature restrictions defined',
        'severity'   : 'Low',
    },
}


class HeaderInspector:
    """
    Inspects HTTP response headers of the target application passively.
    Checks for missing or misconfigured security headers.
    No additional requests are made beyond the initial page fetch.
    """

    def __init__(self, session: requests.Session,
                 scan_manager, auth: dict = None):
        self.session      = session
        self.scan_manager = scan_manager
        self.auth         = auth

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, endpoints: list) -> list:
        if not self.scan_manager.is_active('headers'):
            return []

        findings = []
        print("  [Headers] Starting security header inspection...")

        # Use target URL directly if no endpoints discovered
        if not endpoints:
            base_url = config.TARGET_URL.rstrip('/')
        else:
            base_url = self._get_base_url(endpoints)

        print(f"  [Headers] Inspecting headers at: {base_url}")

        try:
            response = self.session.get(
                base_url,
                timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
        except Exception as e:
            print(f"  [Headers] Could not fetch {base_url}: {e}")
            return []

        # Check each security header
        missing  = []
        present  = []

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in {h.lower()
                                       for h in response.headers}:
                missing.append((header, info))
                print(f"  [Headers] ✗ Missing: {header} "
                      f"[{info['severity']}] — {info['risk']}")
            else:
                present.append(header)
                print(f"  [Headers] ✓ Present: {header}")

        # Create one finding per missing header
        for header, info in missing:
            findings.append(self._make_finding(
                url      = base_url,
                header   = header,
                risk     = info['risk'],
                severity = info['severity']
            ))

        print(f"  [Headers] Done. Found {len(findings)} missing "
              f"header(s) ({len(present)} present).")
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_base_url(self, endpoints: list) -> str:
        """Extract the base application URL from the endpoint list."""
        from urllib.parse import urlparse
        first_url = endpoints[0]['url']
        parsed    = urlparse(first_url)
        # Return scheme + host + first path segment
        parts = parsed.path.split('/')
        if len(parts) >= 2:
            base_path = '/' + parts[1]  # e.g. /dvwa
        else:
            base_path = '/'
        return f"{parsed.scheme}://{parsed.netloc}{base_path}"

    def _make_finding(self, url, header,
                      risk, severity) -> dict:
        return {
            'type'             : 'headers',
            'owasp'            : 'A05:2021 - Security Misconfiguration',
            'url'              : url,
            'method'           : 'GET',
            'parameter'        : header,
            'payload'          : 'N/A',
            'technique'        : 'header-inspection',
            'evidence_dynamic' : f"Header '{header}' is missing. "
                                 f"Risk: {risk}",
            'evidence_static'  : None,
            'confidence'       : 0.65,
            'severity'         : severity,
            'module'           : 'dynamic',
            'finding_type'     : 3,
        }