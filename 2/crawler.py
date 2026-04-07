# ── dynamic/crawler.py ───────────────────────────────────────────────────────

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import config


class Crawler:
    """
    Crawls the target web application and builds a list of endpoints.
    Each endpoint contains: URL, HTTP method, and injectable parameters.
    Only URLs within the original target domain are visited (scope guard).
    """

    def __init__(self, base_url: str):
        self.base_url   = base_url.rstrip('/')
        self.domain     = urlparse(base_url).netloc
        self.visited    = set()
        self.endpoints  = []
        self.session    = requests.Session()
        self.session.headers.update(config.REQUEST_HEADERS)

    # ── Public method ─────────────────────────────────────────────────────────

    def crawl(self) -> list:
        """
        Start crawling from base_url.
        Returns a list of endpoint dicts ready for the injectors.
        """
        print(f"  [Crawler] Starting crawl on: {self.base_url}")
        self._visit(self.base_url)
        print(f"  [Crawler] Done. Found {len(self.endpoints)} endpoint(s).")
        return self.endpoints

    # ── Internal methods ──────────────────────────────────────────────────────

    def _visit(self, url: str):
        """Visit a URL, extract links and forms, recurse into new URLs."""

        # Scope guard — never leave the target domain
        if not self._in_scope(url):
            return

        # Avoid revisiting
        clean_url = url.split('#')[0]          # strip fragments
        if clean_url in self.visited:
            return
        self.visited.add(clean_url)

        # Respect max crawl limit
        if len(self.visited) > config.MAX_CRAWL_PAGES:
            return

        # Fetch the page
        try:
            response = self.session.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                allow_redirects=True
            )
        except Exception as e:
            print(f"  [Crawler] Could not reach {url}: {e}")
            return

        print(f"  [Crawler] Visited: {url} [{response.status_code}]")

        soup = BeautifulSoup(response.text, 'html.parser')

        # ── 1. Collect URL query parameters as GET endpoints ─────────────────
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            self._add_endpoint(
                url   = url,
                method= "GET",
                params= {k: v[0] for k, v in params.items()}
            )

        # ── 2. Collect forms ──────────────────────────────────────────────────
        for form in soup.find_all('form'):
            self._process_form(url, form)

        # ── 3. Follow links ───────────────────────────────────────────────────
        for tag in soup.find_all('a', href=True):
            href     = tag['href'].strip()
            full_url = urljoin(url, href)
            self._visit(full_url)

    def _process_form(self, page_url: str, form):
        """Extract form action, method, and input field names."""
        action = form.get('action', '')
        method = form.get('method', 'get').upper()

        # Resolve relative action URLs
        if action:
            action_url = urljoin(page_url, action)
        else:
            action_url = page_url

        # Scope guard on form action
        if not self._in_scope(action_url):
            return

        # Collect all input/textarea/select fields
        params = {}
        for tag in form.find_all(['input', 'textarea', 'select']):
            name  = tag.get('name')
            value = tag.get('value', 'test')
            if name:
                params[name] = value

        if params:
            self._add_endpoint(
                url   = action_url,
                method= method,
                params= params
            )

    def _add_endpoint(self, url: str, method: str, params: dict):
        """Add an endpoint to the list, avoiding exact duplicates."""
        endpoint = {
            'url'   : url,
            'method': method,
            'params': params
        }
        # Avoid duplicates (same url + method + param names)
        key = (url, method, frozenset(params.keys()))
        if key not in {(e['url'], e['method'], frozenset(e['params'].keys()))
                       for e in self.endpoints}:
            self.endpoints.append(endpoint)

    def _in_scope(self, url: str) -> bool:
        """Return True if the URL belongs to the target domain."""
        try:
            parsed = urlparse(url)
            # Must be http or https
            if parsed.scheme not in ('http', 'https'):
                return False
            # Must match target domain (including subdomains)
            return parsed.netloc == self.domain or \
                   parsed.netloc.endswith('.' + self.domain)
        except Exception:
            return False
