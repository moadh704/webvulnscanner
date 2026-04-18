# ── dynamic/crawler.py ───────────────────────────────────────────────────────

import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

import config

# ── Common REST API paths to probe ────────────────────────────────────────────
API_WORDLIST = [
    # Generic REST patterns
    '/api/users', '/api/user', '/api/products', '/api/product',
    '/api/orders', '/api/order', '/api/items', '/api/item',
    '/api/accounts', '/api/account', '/api/admin', '/api/profile',
    '/api/v1/users', '/api/v1/products', '/api/v2/users',
    '/rest/user', '/rest/users', '/rest/products',
    # Juice Shop specific
    '/api/Users', '/api/Products', '/api/BasketItems',
    '/rest/user/whoami', '/rest/products/search',
    # Common admin/debug endpoints
    '/api/health', '/api/status', '/api/info',
]


class Crawler:
    """
    Crawls the target web application and builds a list of endpoints.
    Supports:
    - Form-based authentication (DVWA)
    - robots.txt / sitemap.xml parsing
    - REST API discovery via common path fuzzing
    - JSON response detection
    """

    def __init__(self, base_url: str, auth: dict = None):
        self.base_url  = base_url.rstrip('/')
        self.domain    = urlparse(base_url).netloc
        self.visited   = set()
        self.endpoints = []
        self.auth      = auth
        self.session   = requests.Session()
        self.session.headers.update(config.REQUEST_HEADERS)

    def crawl(self) -> list:
        if self.auth:
            self._authenticate()
        print(f"  [Crawler] Starting crawl on: {self.base_url}")

        # Test connectivity first
        try:
            self.session.get(
                self.base_url, timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
        except Exception as e:
            print(f"  [Crawler] Cannot reach target: {e}")
            print(f"  [Crawler] Aborting scan.")
            return []

        self._visit(self.base_url)

        # ── REST API discovery ─────────────────────────────────────────────
        self._discover_from_robots()
        self._discover_api_endpoints()

        print(f"  [Crawler] Done. Found {len(self.endpoints)} endpoint(s).")
        return self.endpoints

    def _authenticate(self):
        login_url = self.auth.get('url')
        if not login_url:
            return
        print(f"  [Crawler] Authenticating at: {login_url}")
        try:
            resp = self.session.get(login_url, timeout=config.REQUEST_TIMEOUT)
            soup = BeautifulSoup(resp.text, 'html.parser')
            post_data = {}
            for hidden in soup.find_all('input', type='hidden'):
                name = hidden.get('name')
                value = hidden.get('value', '')
                if name:
                    post_data[name] = value
            post_data[self.auth['username_field']] = self.auth['username']
            post_data[self.auth['password_field']] = self.auth['password']
            for k, v in self.auth.get('extra_fields', {}).items():
                post_data[k] = v
            login_resp = self.session.post(
                login_url, data=post_data,
                timeout=config.REQUEST_TIMEOUT, allow_redirects=True
            )
            if 'login' not in login_resp.url.lower():
                print(f"  [Crawler] Authentication successful.")
            else:
                print(f"  [Crawler] Warning: may not be authenticated.")
        except Exception as e:
            print(f"  [Crawler] Authentication failed: {e}")

    # Pages that should never be visited — destructive or session-breaking
    NEVER_VISIT = [
        'setup.php', 'logout.php', 'phpinfo.php',
    ]

    def _visit(self, url: str):
        if not self._in_scope(url):
            return
        clean_url = url.split('#')[0]

        # Never visit destructive pages
        if any(skip in clean_url for skip in self.NEVER_VISIT):
            print(f"  [Crawler] Skipped (protected): {clean_url}")
            return

        if clean_url in self.visited:
            return
        self.visited.add(clean_url)
        if len(self.visited) > config.MAX_CRAWL_PAGES:
            return
        try:
            response = self.session.get(
                url, timeout=config.REQUEST_TIMEOUT, allow_redirects=True
            )
        except Exception as e:
            print(f"  [Crawler] Could not reach {url}: {e}")
            return
        if 'login' in response.url.lower() and url != response.url:
            print(f"  [Crawler] Skipped (auth redirect): {url}")
            return
        print(f"  [Crawler] Visited: {url} [{response.status_code}]")

        # Check if JSON response — it's an API endpoint
        if self._is_json(response):
            self._add_api_endpoint(url)

        soup = BeautifulSoup(response.text, 'html.parser')
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            self._add_endpoint(url, "GET", {k: v[0] for k, v in params.items()})
        for form in soup.find_all('form'):
            self._process_form(url, form)
        for tag in soup.find_all('a', href=True):
            full_url = urljoin(url, tag['href'].strip())
            self._visit(full_url)

    # ── REST API Discovery ────────────────────────────────────────────────────

    def _discover_from_robots(self):
        """Parse robots.txt and sitemap.xml for hidden paths."""
        base = self._get_root_url()

        # robots.txt
        try:
            r = self.session.get(
                f"{base}/robots.txt",
                timeout=config.REQUEST_TIMEOUT
            )
            if r.status_code == 200 and 'html' not in r.headers.get(
                    'content-type', ''):
                for line in r.text.splitlines():
                    if line.lower().startswith(('disallow:', 'allow:')):
                        path = line.split(':', 1)[-1].strip()
                        if path and path != '/':
                            url = f"{base}{path}"
                            if self._in_scope(url):
                                self._probe_api_path(url)
        except Exception:
            pass

        # sitemap.xml
        try:
            r = self.session.get(
                f"{base}/sitemap.xml",
                timeout=config.REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'xml')
                for loc in soup.find_all('loc'):
                    url = loc.text.strip()
                    if self._in_scope(url):
                        self._probe_api_path(url)
        except Exception:
            pass

    def _discover_api_endpoints(self):
        """Probe common REST API paths and add any that respond with JSON."""
        base = self._get_root_url()
        found = 0

        for path in API_WORDLIST:
            url = f"{base}{path}"
            if url in self.visited:
                continue
            result = self._probe_api_path(url)
            if result:
                found += 1

        if found > 0:
            print(f"  [Crawler] API discovery: found {found} "
                  f"REST endpoint(s).")

    def _probe_api_path(self, url: str) -> bool:
        """
        Probe a single URL. If it returns JSON or 200,
        add it as an endpoint. Returns True if found.
        """
        try:
            r = self.session.get(
                url, timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
            self.visited.add(url)

            if r.status_code in (200, 201) and len(r.text) > 10:
                if self._is_json(r):
                    print(f"  [Crawler] API endpoint: {url} "
                          f"[{r.status_code}] (JSON)")
                    self._add_api_endpoint(url)
                    # Try probing /{id} variants
                    for id_val in ['1', '2']:
                        id_url = f"{url.rstrip('/')}/{id_val}"
                        try:
                            r2 = self.session.get(
                                id_url,
                                timeout=config.REQUEST_TIMEOUT
                            )
                            if r2.status_code == 200 and self._is_json(r2):
                                self._add_api_endpoint(id_url)
                        except Exception:
                            pass
                    return True
        except Exception:
            pass
        return False

    def _add_api_endpoint(self, url: str):
        """Add a REST API endpoint with id parameter."""
        clean_url = url.split('#')[0]
        # Extract id from URL path if present
        parts = urlparse(clean_url).path.rstrip('/').split('/')
        last  = parts[-1]

        if last.isdigit():
            # URL like /api/Users/1 — parameter is in path
            base_url = clean_url.rsplit('/', 1)[0]
            params   = {'id': last}
        else:
            params   = {}

        self._add_endpoint(clean_url, 'GET', params)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_json(self, response) -> bool:
        """Check if response contains JSON data."""
        content_type = response.headers.get('content-type', '')
        if 'json' in content_type:
            return True
        try:
            json.loads(response.text)
            return True
        except Exception:
            return False

    def _get_root_url(self) -> str:
        """Get the root URL (scheme + host) of the target."""
        parsed = urlparse(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _process_form(self, page_url: str, form):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        action_url = urljoin(page_url, action) if action else page_url
        if not self._in_scope(action_url):
            return
        params = {}
        for tag in form.find_all(['input', 'textarea', 'select']):
            name = tag.get('name')
            if name:
                params[name] = tag.get('value', 'test')
        if params:
            self._add_endpoint(action_url, method, params)

    def _add_endpoint(self, url: str, method: str, params: dict):
        clean_url = url.split('#')[0]
        if not clean_url:
            return
        key = (clean_url, method, frozenset(params.keys()))
        if key not in {(e['url'], e['method'], frozenset(e['params'].keys()))
                       for e in self.endpoints}:
            self.endpoints.append({
                'url'    : clean_url,
                'method' : method,
                'params' : params
            })

    def _in_scope(self, url: str) -> bool:
        try:
            parsed      = urlparse(url)
            base_parsed = urlparse(self.base_url)
            if parsed.scheme not in ('http', 'https'):
                return False
            if parsed.netloc != self.domain and \
               not parsed.netloc.endswith('.' + self.domain):
                return False
            base_path = base_parsed.path.rstrip('/')
            if '.' in base_path.split('/')[-1]:
                base_path = '/'.join(base_path.split('/')[:-1])
            base_path = base_path.rstrip('/') + '/'
            if base_path and base_path != '/' and \
               not parsed.path.startswith(base_path):
                return False
            return True
        except Exception:
            return False