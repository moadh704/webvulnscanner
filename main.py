# ── main.py ───────────────────────────────────────────────────────────────────
"""
WebVulnScanner - Hybrid Static and Dynamic Web Vulnerability Analyzer
Usage:
    python main.py --url http://target.com
    python main.py --url http://target.com --src ./source/
    python main.py --url http://target.com --scan sqli,xss
    python main.py --url http://target.com --src ./source/ --scan sqli,cmdi
    python main.py --url http://target.com --no-ai --quiet
    python main.py --url http://localhost/dvwa --difficulty high   (DVWA only)
"""

import argparse
import os
import sys
import io
import time
from urllib.parse import urlparse

import config
from core.scan_manager import ScanManager


class _QuietMode:
    """Context manager — suppresses stdout when quiet mode is on."""
    def __init__(self, active: bool):
        self.active = active
        self._old   = None

    def __enter__(self):
        if self.active:
            self._old  = sys.stdout
            sys.stdout = io.StringIO()
        return self

    def __exit__(self, *_):
        if self.active and self._old:
            sys.stdout = self._old


# ── Rich progress helpers ──────────────────────────────────────────────────────

def _make_progress():
    """Create a Rich progress bar with phase display."""
    try:
        from rich.progress import (
            Progress, SpinnerColumn, BarColumn,
            TextColumn, TimeElapsedColumn, TaskProgressColumn
        )
        from rich.console import Console
        from rich.theme import Theme

        theme = Theme({
            "progress.description": "bold cyan",
            "progress.percentage" : "bold green",
            "bar.complete"        : "green",
            "bar.finished"        : "bold green",
        })
        console = Console(theme=theme)
        progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        return progress
    except ImportError:
        return None


class PhaseTracker:
    """
    Tracks scan phases and shows a clean progress display using Rich.
    Falls back to plain text if Rich is not available.
    """

    PHASES = [
        ("🔍 Static Analysis",    "Scanning source code with Semgrep rules"),
        ("🌐 Crawling Target",     "Discovering endpoints and parameters"),
        ("💉 Injection Testing",   "Running dynamic vulnerability injectors"),
        ("🔗 Correlation Engine",  "Matching static and dynamic findings"),
        ("🤖 AI Enhancement",      "Reviewing findings and generating remediations"),
        ("📄 Generating Report",   "Writing HTML and JSON reports"),
    ]

    def __init__(self, mode: str, modules: list, use_ai: bool):
        self.mode    = mode
        self.modules = modules
        self.use_ai  = use_ai
        self._rich   = None
        self._task   = None
        self._phase  = 0
        self._total  = self._count_phases()

        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text
            self._console = Console()
            self._has_rich = True
        except ImportError:
            self._has_rich = False

    def _count_phases(self) -> int:
        count = 0
        if self.mode in ("hybrid", "static"):
            count += 1  # static
        if self.mode in ("hybrid", "dynamic", "dynamic-only"):
            count += 1  # crawl
            count += len(self.modules)  # one per module
        count += 1  # correlation
        if self.use_ai:
            count += 1  # AI
        count += 1  # report
        return max(count, 1)

    def start(self, target_url: str, source_dir: str,
              modules: list, ai_provider: str):
        """Print the scan header."""
        if self._has_rich:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich import box

            c = Console()
            c.print()
            c.print(
                Panel.fit(
                   f"[bold cyan]WebVulnScanner v1.0[/bold cyan]  "
                   f"[dim]Hybrid Web Vulnerability Scanner[/dim]",
                    border_style="cyan"
                )
            )
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column(style="dim")
            t.add_column(style="bold white")
            if target_url:
                t.add_row("Target URL",  target_url)
            if source_dir:
                t.add_row("Source Dir",  source_dir)
            t.add_row("Mode",        self.mode)
            t.add_row("Modules",     ", ".join(modules))
            t.add_row("AI Provider", ai_provider if self.use_ai else "disabled")
            c.print(t)
            c.print()
        else:
            print("=" * 60)
            print("WebVulnScanner v1.0 — Hybrid Web Vulnerability Scanner")
            print("=" * 60)
            print(f"  Target  : {target_url or 'N/A'}")
            print(f"  Mode    : {self.mode}")
            print(f"  Modules : {', '.join(modules)}")
            print()

    def phase(self, name: str, detail: str = ""):
        """Announce a new phase."""
        self._phase += 1
        pct = int((self._phase / self._total) * 100)

        if self._has_rich:
            from rich.console import Console
            c = Console()
            bar_filled = int(pct / 5)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            c.print(
                f"  [dim][{self._phase}/{self._total}][/dim]  "
                f"[cyan]{bar}[/cyan]  [bold]{name}[/bold]"
                + (f"  [dim]{detail}[/dim]" if detail else "")
            )
        else:
            print(f"[{self._phase}/{self._total}] {name}"
                  + (f" — {detail}" if detail else ""))

    def done(self, findings: list, paths: dict):
        """Print the final summary."""
        retained = [f for f in findings if f.get('status') != 'dismissed']
        dismissed = len(findings) - len(retained)

        cr = sum(1 for f in retained if f.get('severity') == 'Critical')
        hi = sum(1 for f in retained if f.get('severity') == 'High')
        me = sum(1 for f in retained if f.get('severity') == 'Medium')
        lo = sum(1 for f in retained if f.get('severity') == 'Low')
        t1 = sum(1 for f in retained if f.get('finding_type') == 1)
        t2 = sum(1 for f in retained if f.get('finding_type') == 2)
        t3 = sum(1 for f in retained if f.get('finding_type') == 3)

        if self._has_rich:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            from rich import box

            c = Console()
            c.print()

            t = Table(
                title="Scan Summary",
                box=box.ROUNDED,
                border_style="cyan",
                show_header=True,
                header_style="bold cyan"
            )
            t.add_column("Category",  style="dim", width=22)
            t.add_column("Count",     justify="right", width=8)
            t.add_column("Details",   style="dim")

            t.add_row("Total Findings",
                      f"[bold white]{len(retained)}[/]", "")
            t.add_section()
            if cr: t.add_row("Critical",
                              f"[bold red]{cr}[/]", "Immediate action required")
            if hi: t.add_row("High",
                              f"[bold yellow]{hi}[/]", "High risk")
            if me: t.add_row("Medium",
                              f"[yellow]{me}[/]", "Medium risk")
            if lo: t.add_row("Low",
                              f"[green]{lo}[/]", "Low risk")
            t.add_section()
            if t1: t.add_row("✓ Verified",
                              f"[bold green]{t1}[/]",
                              "Static + Dynamic confirmed")
            if t2: t.add_row("⚠ Candidate",
                              f"[yellow]{t2}[/]",
                              "Static only, AI reviewed")
            if t3: t.add_row("◎ Detected",
                              f"[cyan]{t3}[/]",
                              "Runtime only")
            if dismissed:
                t.add_section()
                t.add_row("Dismissed (FP)",
                          f"[dim]{dismissed}[/]",
                          "Removed by AI as false positives")

            c.print(t)
            c.print()
            if paths.get('html'):
                c.print(f"  [bold green]✓[/] HTML report → [cyan]{paths['html']}[/]")
            if paths.get('json'):
                c.print(f"  [bold green]✓[/] JSON report → [cyan]{paths['json']}[/]")
            c.print()
            c.print(
                Panel.fit(
                    "[bold green]✓ Scan complete[/bold green]",
                    border_style="green"
                )
            )
        else:
            print("=" * 60)
            print(f"  SCAN COMPLETE — {len(retained)} findings")
            if cr: print(f"  Critical : {cr}")
            if hi: print(f"  High     : {hi}")
            if me: print(f"  Medium   : {me}")
            if lo: print(f"  Low      : {lo}")
            print("=" * 60)
            if paths.get('html'):
                print(f"  HTML → {paths['html']}")
            if paths.get('json'):
                print(f"  JSON → {paths['json']}")


# ── Argument parsing ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScanner - Hybrid Web Vulnerability Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--url", type=str,
        help="Target URL to scan\nExample: --url http://dvwa.local"
    )
    parser.add_argument(
        "--src", type=str, default=None,
        help="Source code directory (enables hybrid mode)\nExample: --src ./dvwa-source/"
    )
    parser.add_argument(
        "--scan", type=str, default=None,
        help="Modules to run (default: all)\n"
             "Options: sqli, xss, cmdi, traversal, idor, headers\n"
             "Example: --scan sqli,xss"
    )
    parser.add_argument(
        "--mode", type=str,
        choices=["full", "static", "dynamic"], default="full",
        help="Analysis mode (default: full)\n"
             "  full    - static + dynamic\n"
             "  static  - static only\n"
             "  dynamic - dynamic only"
    )
    parser.add_argument(
        "--output", type=str, default="reports",
        help="Output directory (default: reports)"
    )
    parser.add_argument(
        "--output-format", type=str,
        choices=["html", "json", "both"], default="both",
        help="Report format (default: both)\n"
             "Options: html, json, both"
    )
    parser.add_argument(
        "--username", type=str, default=None,
        help="Login username\nExample: --username admin"
    )
    parser.add_argument(
        "--password", type=str, default=None,
        help="Login password\nExample: --password secret"
    )
    parser.add_argument(
        "--difficulty", type=str, default=None,
        choices=["low", "medium", "high", "impossible"],
        help="DVWA security level to set after login\n"
             "Options: low, medium, high, impossible\n"
             "Example: --difficulty high\n"
             "(DVWA targets only — ignored otherwise)"
    )
    parser.add_argument(
        "--ai-provider", type=str,
        choices=["groq", "gemini", "none"], default=None,
        help="AI provider override\nOptions: groq, gemini, none"
    )
    parser.add_argument(
        "--no-ai", action="store_true",
        help="Disable AI enhancement layer (faster scans)"
    )
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Request timeout in seconds\nExample: --timeout 15"
    )
    parser.add_argument(
        "--max-pages", type=int, default=None,
        help="Max pages to crawl\nExample: --max-pages 100"
    )
    parser.add_argument(
        "--report-name", type=str, default=None,
        help="Custom report filename\nExample: --report-name myscan"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show detailed output for every request"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress all output except findings summary"
    )

    return parser.parse_args()


def validate_args(args):
    errors = []
    if not args.url and not args.src:
        errors.append("At least one of --url or --src must be provided.")
    if args.mode == "static" and not args.src:
        errors.append("--mode static requires --src.")
    if args.mode == "dynamic" and not args.url:
        errors.append("--mode dynamic requires --url.")
    if args.src and not os.path.isdir(args.src):
        errors.append(f"Source directory not found: {args.src}")
    if args.verbose and args.quiet:
        errors.append("--verbose and --quiet cannot be used together.")
    if errors:
        for e in errors:
            print(f"[!] Error: {e}")
        sys.exit(1)

    config.TARGET_URL = args.url or ""
    config.SOURCE_DIR = args.src or ""

    # --no-ai overrides --ai-provider
    if args.no_ai:
        config.AI_PROVIDER = "none"
    elif args.ai_provider:
        config.AI_PROVIDER = args.ai_provider

    if args.timeout:
        config.REQUEST_TIMEOUT = args.timeout
    if args.max_pages:
        config.MAX_CRAWL_PAGES = args.max_pages

    # Store output format in config for reporter
    config.OUTPUT_FORMAT = args.output_format


def determine_mode(args):
    if args.mode == "static":
        return "static"
    if args.mode == "dynamic":
        return "dynamic"
    if args.url and args.src:
        return "hybrid"
    return "dynamic-only"


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    args         = parse_args()
    validate_args(args)

    scan_manager = ScanManager(args.scan)
    mode         = determine_mode(args)
    use_ai       = config.AI_PROVIDER != "none"

    # Suppress crawler/injector verbose output in quiet mode
    config.QUIET   = args.quiet
    config.VERBOSE = args.verbose

    tracker = PhaseTracker(mode, scan_manager.active_modules(), use_ai)
    tracker.start(
        target_url = args.url or "",
        source_dir = args.src or "",
        modules    = scan_manager.active_modules(),
        ai_provider= config.AI_PROVIDER,
    )

    all_findings    = []
    static_findings = []
    quiet           = args.quiet

    # ── Static Phase ──────────────────────────────────────────────────────────
    if mode in ("hybrid", "static") and config.SOURCE_DIR:
        tracker.phase("Static Analysis", f"Scanning {config.SOURCE_DIR}")
        from static.scanner import StaticScanner
        with _QuietMode(quiet):
            static_findings = StaticScanner(scan_manager).run(config.SOURCE_DIR)
        all_findings.extend(static_findings)

    # ── Dynamic Phase ─────────────────────────────────────────────────────────
    if mode in ("hybrid", "dynamic", "dynamic-only") and config.TARGET_URL:

        # ── Crawl ─────────────────────────────────────────────────────────────
        tracker.phase("Crawling Target", config.TARGET_URL)
        from dynamic.crawler import Crawler, detect_login_form

        # Build the auth dict if credentials are supplied OR if the target
        # is DVWA (in which case we use its well-known default credentials).
        # Login-form field names are auto-detected from the page itself so
        # the same code path works for DVWA, bWAPP, Mutillidae, and any
        # other application — no per-target hardcoding.
        auth = None
        if (args.username and args.password) or \
           'dvwa' in config.TARGET_URL.lower():
            # Resolve credentials: explicit args win, otherwise fall back
            # to DVWA's well-known defaults so the no-flag invocation
            # against DVWA still works.
            if args.username and args.password:
                creds_user, creds_pass = args.username, args.password
            else:
                creds_user, creds_pass = 'admin', 'password'

            parsed_target = urlparse(config.TARGET_URL)
            # Detect application sub-path (e.g., /dvwa, /bWAPP) so login.php
            # resolves relative to the target, not the host root.
            base_path = '/'.join(
                parsed_target.path.rstrip('/').split('/')[:2]
            )
            login_url = (f"{parsed_target.scheme}://"
                         f"{parsed_target.netloc}{base_path}/login.php")

            # Auto-detect the login form's field names by reading the page.
            # This lets the scanner authenticate against any app without
            # per-target hardcoding of input names.
            with _QuietMode(quiet):
                detected = detect_login_form(login_url)

            auth = {
                'url'            : login_url,
                'username'       : creds_user,
                'password'       : creds_pass,
                'username_field' : detected['username_field'],
                'password_field' : detected['password_field'],
                'extra_fields'   : detected['extra_fields'],
            }

        crawl_url = config.TARGET_URL.rstrip('/')
        if 'dvwa' in crawl_url.lower() and not crawl_url.endswith('.php'):
            crawl_url += '/index.php'

        crawler = Crawler(crawl_url, auth=auth)

        # ── DVWA difficulty selection ─────────────────────────────────────
        # If --difficulty is supplied AND the target is DVWA, the crawler
        # authenticates first and then sets the security level. The level
        # is bound to the session cookie, so all subsequent injector calls
        # share that level.
        if args.difficulty and 'dvwa' in crawl_url.lower():
            with _QuietMode(quiet):
                if auth:
                    crawler._authenticate()
                    crawler.set_dvwa_security_level(args.difficulty)
                    # mark auth as already done so crawl() doesn't redo it
                    crawler.auth = None

        with _QuietMode(quiet):
            endpoints = crawler.crawl()

        # ── Injectors ─────────────────────────────────────────────────────────
        if scan_manager.is_active('sqli'):
            tracker.phase("SQL Injection", f"Testing {len(endpoints)} endpoint(s)")
            from dynamic.sqli_injector import SQLiInjector
            with _QuietMode(quiet):
                all_findings.extend(
                    SQLiInjector(crawler.session, scan_manager, auth=auth).run(endpoints)
                )

        if scan_manager.is_active('xss'):
            tracker.phase("Cross-Site Scripting (XSS)", f"Testing {len(endpoints)} endpoint(s)")
            from dynamic.xss_injector import XSSInjector
            with _QuietMode(quiet):
                all_findings.extend(
                    XSSInjector(crawler.session, scan_manager, auth=auth).run(endpoints)
                )

        if scan_manager.is_active('cmdi'):
            tracker.phase("Command Injection", f"Testing {len(endpoints)} endpoint(s)")
            from dynamic.cmdi_injector import CMDiInjector
            with _QuietMode(quiet):
                all_findings.extend(
                    CMDiInjector(crawler.session, scan_manager, auth=auth).run(endpoints)
                )

        if scan_manager.is_active('traversal'):
            tracker.phase("Path Traversal", f"Testing {len(endpoints)} endpoint(s)")
            from dynamic.traversal_injector import TraversalInjector
            with _QuietMode(quiet):
                all_findings.extend(
                    TraversalInjector(crawler.session, scan_manager, auth=auth).run(endpoints)
                )

        if scan_manager.is_active('idor'):
            tracker.phase("IDOR Enumeration", f"Testing {len(endpoints)} endpoint(s)")
            from dynamic.idor_enumerator import IDOREnumerator
            with _QuietMode(quiet):
                all_findings.extend(
                    IDOREnumerator(crawler.session, scan_manager, auth=auth).run(endpoints)
                )

        if scan_manager.is_active('headers'):
            tracker.phase("Security Headers", config.TARGET_URL)
            from dynamic.header_inspector import HeaderInspector
            with _QuietMode(quiet):
                all_findings.extend(
                    HeaderInspector(crawler.session, scan_manager, auth=auth).run(endpoints)
                )

    # ── Correlation ───────────────────────────────────────────────────────────
    if all_findings:
        tracker.phase("Correlation Engine",
                      f"{len(static_findings)} static + "
                      f"{len(all_findings) - len(static_findings)} dynamic")
        from core.correlator import Correlator
        with _QuietMode(quiet):
            all_findings = Correlator().correlate(all_findings)

    # ── AI Enhancement ────────────────────────────────────────────────────────
    if all_findings and use_ai:
        tracker.phase("AI Enhancement",
                      f"Reviewing {len(all_findings)} finding(s) with {config.AI_PROVIDER}")
        from core.ai_provider import AIEnhancer
        with _QuietMode(quiet):
            all_findings = AIEnhancer().enhance(all_findings)

    # ── Report ────────────────────────────────────────────────────────────────
    paths = {}
    if all_findings:
        tracker.phase("Generating Report", args.output)
        from core.reporter import Reporter
        with _QuietMode(quiet):
            paths = Reporter(
                all_findings, args.output,
                report_name   = args.report_name,
                output_format = getattr(args, 'output_format', 'both')
            ).generate()
    else:
        if not quiet:
            print("\n  No findings to report.")

    tracker.done(all_findings, paths)


if __name__ == "__main__":
    main()