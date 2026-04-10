# ── dynamic/crawler.py ───────────────────────────────────────────────────────

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

import config


class Crawler:
    """
    Crawls the target web application and builds a list of endpoints.
    Supports form-based authentication for protected apps like DVWA.
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
        self._visit(self.base_url)
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

    def _visit(self, url: str):
        if not self._in_scope(url):
            return
        clean_url = url.split('#')[0]
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
        clean_url = url.split('#')[0]   # strip fragment — never sent to server
        if not clean_url:
            return
        key = (clean_url, method, frozenset(params.keys()))
        if key not in {(e['url'], e['method'], frozenset(e['params'].keys()))
                       for e in self.endpoints}:
            self.endpoints.append({'url': clean_url, 'method': method, 'params': params})

    def _in_scope(self, url: str) -> bool:
        try:
            parsed      = urlparse(url)
            base_parsed = urlparse(self.base_url)
            if parsed.scheme not in ('http', 'https'):
                return False
            # Domain must match
            if parsed.netloc != self.domain and \
               not parsed.netloc.endswith('.' + self.domain):
                return False
            # Get base directory (strip filename if present)
            base_path = base_parsed.path.rstrip('/')
            if '.' in base_path.split('/')[-1]:
                # Last segment is a file — use its directory
                base_path = '/'.join(base_path.split('/')[:-1])
            base_path = base_path.rstrip('/') + '/'
            if base_path and base_path != '/' and \
               not parsed.path.startswith(base_path):
                return False
            return True
        except Exception:
            return False