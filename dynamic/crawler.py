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


# ── Destructive parameters / pages ────────────────────────────────────────────
# These markers identify forms or endpoints that, if exercised by the
# injectors, would damage the target application's state (wipe DB, change
# password, log out, change difficulty, etc.). The crawler must never add
# them as endpoints.
DESTRUCTIVE_PARAM_NAMES = {
    'create_db', 'reset_db', 'drop_db',
    'security',                      # DVWA security level setter
    'change',                        # password-change submit
    'password_new', 'password_conf', # password-change fields
    'logout', 'submit_logout',
}

# Destructive substrings to match against the URL itself. These cover both
# DVWA's per-page destructives (setup.php, security.php) and Mutillidae's
# query-string-based destructives (?do=toggle-enforce-ssl, ?do=logout, etc.)
# which are not separate pages but verbs against index.php.
DESTRUCTIVE_PATH_FRAGMENTS = [
    'setup.php', 'logout.php', 'phpinfo.php',
    'security.php',                  # DVWA difficulty page
    'password.php',                  # DVWA password change
    # Mutillidae: query-string actions on index.php that mutate session state
    'do=toggle-enforce-ssl',         # forces session to HTTPS — breaks crawl
    'do=toggle-security',            # changes security level
    'do=toggle-hints',               # toggles hint mode
    'do=logout',                     # ends session
    'do=reset-database',             # wipes DB
    # Mutillidae: setup page (separate from DVWA's setup.php)
    'set-up-database.php',
]


# ── Login form auto-detection ─────────────────────────────────────────────────

def _parse_login_form(html: str) -> dict:
    """
    Parse a single page's HTML and return the login-form fields if a form
    with a password input is present. Returns None if no such form exists.
    """
    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return None

    # The login form is the form that contains a password input.
    login_form = None
    for form in soup.find_all('form'):
        if form.find('input', {'type': 'password'}):
            login_form = form
            break
    if login_form is None:
        return None

    # Password field — read the name straight off the type=password input.
    pw_input       = login_form.find('input', {'type': 'password'})
    password_field = pw_input.get('name') or 'password'

    # Username field — first text/email input in the form. Login forms
    # almost always place the username before the password input.
    username_field = 'username'
    for inp in login_form.find_all('input'):
        itype = (inp.get('type') or 'text').lower()
        if itype in ('text', 'email') and inp.get('name'):
            username_field = inp['name']
            break

    # Submit control — capture name + value so the request is byte-for-byte
    # what the browser would send (some apps gate on a specific name=value,
    # e.g. bWAPP requires form=submit).
    extra_fields = {}
    submit = (
        login_form.find('button', {'type': 'submit'})
        or login_form.find('input', {'type': 'submit'})
        or login_form.find('button')
    )
    if submit and submit.get('name'):
        extra_fields[submit['name']] = submit.get('value') or 'submit'

    return {
        'username_field' : username_field,
        'password_field' : password_field,
        'extra_fields'   : extra_fields,
    }


def _fetch_and_parse(url: str, timeout: int) -> dict:
    """Fetch a URL and run _parse_login_form on the response. Returns the
    parsed dict, or None on any failure / no-form-found."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers=config.REQUEST_HEADERS,
            allow_redirects=True,
        )
    except Exception:
        return None
    return _parse_login_form(resp.text)


def detect_login_form(login_url: str, timeout: int = 10) -> dict:
    """
    Inspect a login page and auto-detect its form fields and effective URL.

    Different intentionally-vulnerable applications use different field
    names AND different URL patterns. DVWA uses /login.php with
    username/password/Login fields; bWAPP uses /login.php with
    login/password/form fields; Mutillidae routes login through a query
    string at /index.php?page=login.php. Rather than hardcode each target,
    we fetch the candidate login pages and read the names off the actual
    HTML.

    Returns a dict with four keys:
      - login_url      : the URL that actually served the form (may differ
                         from the input login_url if a fallback worked)
      - username_field : name attribute of the username/login input
      - password_field : name attribute of the password input
      - extra_fields   : {name: value} for the form's submit button so we
                         replay it exactly as the server expects

    Hidden CSRF / session tokens are NOT captured here — _authenticate()
    already harvests them at login time.

    If no form is found at any candidate URL, falls back to common
    defaults so the caller still gets a usable dict.
    """
    fallback = {
        'login_url'      : login_url,
        'username_field' : 'username',
        'password_field' : 'password',
        'extra_fields'   : {},
    }

    # 1. Try the URL as given (the common case — DVWA, bWAPP).
    parsed = _fetch_and_parse(login_url, timeout)
    if parsed:
        print(f"  [Auth] Detected login form at {login_url}: "
              f"user='{parsed['username_field']}', "
              f"pass='{parsed['password_field']}', "
              f"submit={parsed['extra_fields'] or '(none)'}")
        return {'login_url': login_url, **parsed}

    # 2. Try common alternative URL patterns (Mutillidae-style routing).
    #    Strip /login.php off the input URL to get the application base,
    #    then probe known query-string login routes underneath it.
    parsed_url = urlparse(login_url)
    base       = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if parsed_url.path.endswith('/login.php'):
        app_base = parsed_url.path[:-len('/login.php')]
    else:
        app_base = parsed_url.path.rsplit('/', 1)[0]
    app_base = app_base.rstrip('/')

    candidates = [
        f"{base}{app_base}/index.php?page=login.php",
        f"{base}{app_base}/index.php?page=login",
    ]

    for candidate in candidates:
        if candidate == login_url:
            continue
        parsed = _fetch_and_parse(candidate, timeout)
        if parsed:
            print(f"  [Auth] Detected login form at {candidate}: "
                  f"user='{parsed['username_field']}', "
                  f"pass='{parsed['password_field']}', "
                  f"submit={parsed['extra_fields'] or '(none)'}")
            return {'login_url': candidate, **parsed}

    print(f"  [Auth] No password form found at any candidate URL "
          f"(tried {login_url} and {len(candidates)} alternatives) — "
          f"using defaults.")
    return fallback


class Crawler:
    """
    Crawls the target web application and builds a list of endpoints.
    Supports:
    - Form-based authentication (DVWA, bWAPP, Mutillidae, ...)
    - Auto-detected login form fields (see detect_login_form)
    - robots.txt / sitemap.xml parsing
    - REST API discovery via common path fuzzing
    - JSON response detection
    - Destructive-form filtering (never adds DB-reset, security-level, or
      password-change forms to the endpoint list)
    - Optional DVWA security-level setter (call set_dvwa_security_level
      after construction to choose Low / Medium / High / Impossible)
    """

    # Pages that should never be visited — destructive or session-breaking
    NEVER_VISIT = list(DESTRUCTIVE_PATH_FRAGMENTS)

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

        # Test connectivity with configured timeout
        try:
            self.session.get(
                self.base_url, timeout=max(config.REQUEST_TIMEOUT, 20),
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

    # ── DVWA security level setter ────────────────────────────────────────────

    def set_dvwa_security_level(self, level: str) -> bool:
        """
        Set DVWA's session security level (low / medium / high / impossible).
        Must be called AFTER _authenticate() and BEFORE crawl().
        Posts to /security.php with the security parameter so the level
        persists for all subsequent requests in this session.

        Returns True on success, False otherwise.
        """
        level = level.lower()
        if level not in ('low', 'medium', 'high', 'impossible'):
            print(f"  [Crawler] Unknown DVWA level '{level}' — skipping.")
            return False

        # Build the security.php URL relative to the target's base path.
        parsed     = urlparse(self.base_url)
        base_path  = '/'.join(parsed.path.rstrip('/').split('/')[:2])
        sec_url    = (f"{parsed.scheme}://{parsed.netloc}"
                      f"{base_path}/security.php")

        try:
            # GET first so any CSRF / hidden tokens are picked up.
            r1 = self.session.get(sec_url, timeout=config.REQUEST_TIMEOUT)
            soup = BeautifulSoup(r1.text, 'html.parser')
            post_data = {}
            for hidden in soup.find_all('input', type='hidden'):
                name = hidden.get('name')
                if name:
                    post_data[name] = hidden.get('value', '')
            post_data['security']   = level
            post_data['seclev_submit'] = 'Submit'  # DVWA submit button name

            r2 = self.session.post(
                sec_url, data=post_data,
                timeout=config.REQUEST_TIMEOUT, allow_redirects=True
            )
            # DVWA echoes the new level back on the page after submit.
            if level in r2.text.lower():
                print(f"  [Crawler] DVWA security level set to: {level}")
                return True
            print(f"  [Crawler] Warning: could not confirm "
                  f"DVWA level change to '{level}'.")
            return False
        except Exception as e:
            print(f"  [Crawler] Setting DVWA level failed: {e}")
            return False

    # ── Visit logic ───────────────────────────────────────────────────────────

    def _visit(self, url: str):
        if not self._in_scope(url):
            return
        clean_url = url.split('#')[0]

        # Never visit destructive pages
        if self._is_destructive_url(clean_url):
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

        # Use the final URL after any server-side redirects as the base for
        # resolving relative links. Without this, a redirect from
        # /mutillidae → /mutillidae/index.php causes urljoin to produce
        # /index.php?page=X (wrong path) instead of /mutillidae/index.php?page=X.
        effective_url = response.url.split('#')[0]
        if effective_url != clean_url:
            self.visited.add(effective_url)

        # Check if JSON response — it's an API endpoint
        if self._is_json(response):
            self._add_api_endpoint(effective_url)

        soup = BeautifulSoup(response.text, 'html.parser')
        parsed = urlparse(effective_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            self._add_endpoint(effective_url, "GET", {k: v[0] for k, v in params.items()})
        for form in soup.find_all('form'):
            self._process_form(effective_url, form)
        for tag in soup.find_all('a', href=True):
            full_url = urljoin(effective_url, tag['href'].strip())
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

    def _is_destructive_url(self, url: str) -> bool:
        """Check if a URL points to a destructive page (DB reset etc).
        Compares against DESTRUCTIVE_PATH_FRAGMENTS — these match against
        the full URL string (not just the path), so query-string-based
        destructives like '?do=toggle-enforce-ssl' are caught too."""
        url_lower = url.lower()
        return any(frag in url_lower for frag in DESTRUCTIVE_PATH_FRAGMENTS)

    def _is_destructive_form(self, action_url: str, params: dict) -> bool:
        """
        Detect forms whose submission would damage the target — DB reset,
        password change, security-level change, logout. These must never
        be added to the endpoint list because the injectors would otherwise
        POST malformed payloads to them and wipe / corrupt the test target.
        """
        # 1. Destructive page (e.g., setup.php)
        if self._is_destructive_url(action_url):
            return True
        # 2. Destructive parameter present in form fields
        param_keys_lower = {k.lower() for k in params.keys()}
        if param_keys_lower & DESTRUCTIVE_PARAM_NAMES:
            return True
        return False

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

        # ── Destructive-form filter ───────────────────────────────────────
        # Drop forms that would wipe the DB, reset the password, change the
        # security level, or log the session out. This protects the target
        # application from being damaged by the injectors that follow.
        if self._is_destructive_form(action_url, params):
            print(f"  [Crawler] Skipped destructive form: {action_url}")
            return

        if params:
            self._add_endpoint(action_url, method, params)

    def _add_endpoint(self, url: str, method: str, params: dict):
        clean_url = url.split('#')[0]
        if not clean_url:
            return
        # Final defence: never add a destructive endpoint, even if it
        # bypassed the form-level filter (e.g., GET-with-query-string).
        if self._is_destructive_form(clean_url, params):
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
            if base_path and base_path != '/':
                # Normalize the URL's path with a trailing slash so that
                # a sub-path target like "http://localhost/mutillidae"
                # is treated as in-scope when entered without a trailing
                # slash. Without this, "/mutillidae" fails to start with
                # "/mutillidae/" and the very first crawl visit is
                # rejected, leaving us with zero endpoints.
                url_path = parsed.path
                if not url_path.endswith('/'):
                    url_path += '/'
                if not url_path.startswith(base_path):
                    return False
            return True
        except Exception:
            return False