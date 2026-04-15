# ── main.py ───────────────────────────────────────────────────────────────────
"""
WebVulnScanner - Hybrid Static and Dynamic Web Vulnerability Analyzer
Usage:
    python main.py --url http://target.com
    python main.py --url http://target.com --src ./source/
    python main.py --url http://target.com --scan sqli,xss
    python main.py --url http://target.com --src ./source/ --scan sqli,cmdi
"""

import argparse
import os
import sys
from urllib.parse import urlparse

import config
from core.scan_manager import ScanManager


def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScanner - Hybrid Web Vulnerability Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--url",
        type=str,
        help="Target URL to scan (required for dynamic analysis)\n"
             "Example: --url http://dvwa.local"
    )

    parser.add_argument(
        "--src",
        type=str,
        default=None,
        help="Path to source code directory (optional, enables hybrid mode)\n"
             "Example: --src ./dvwa-source/"
    )

    parser.add_argument(
        "--scan",
        type=str,
        default=None,
        help="Comma-separated list of modules to run (default: all)\n"
             "Options: sqli, xss, cmdi, traversal, idor, headers\n"
             "Example: --scan sqli,xss"
    )

    parser.add_argument(
        "--mode",
        type=str,
        choices=["full", "static", "dynamic"],
        default="full",
        help="Analysis mode (default: full)\n"
             "  full    - static + dynamic\n"
             "  static  - static only (requires --src)\n"
             "  dynamic - dynamic only"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Output directory for reports (default: reports)"
    )

    return parser.parse_args()


def validate_args(args):
    """Validate argument combinations and set config values."""
    errors = []

    # At least one of --url or --src must be provided
    if not args.url and not args.src:
        errors.append("At least one of --url or --src must be provided.")

    # Static-only mode requires --src
    if args.mode == "static" and not args.src:
        errors.append("--mode static requires --src to be provided.")

    # Dynamic-only mode requires --url
    if args.mode == "dynamic" and not args.url:
        errors.append("--mode dynamic requires --url to be provided.")

    # Validate source directory exists if provided
    if args.src and not os.path.isdir(args.src):
        errors.append(f"Source directory not found: {args.src}")

    if errors:
        for e in errors:
            print(f"[!] Error: {e}")
        sys.exit(1)

    # Set global config values
    config.TARGET_URL  = args.url or ""
    config.SOURCE_DIR  = args.src or ""


def determine_mode(args):
    """Determine the operating mode based on inputs."""
    if args.mode == "static":
        return "static"
    if args.mode == "dynamic":
        return "dynamic"
    # Full mode: hybrid if both provided, dynamic-only if only URL
    if args.url and args.src:
        return "hybrid"
    return "dynamic-only"


def main():
    print("=" * 60)
    print("  WebVulnScanner v1.0 — Academic Security Research Tool")
    print("=" * 60)

    args        = parse_args()
    validate_args(args)

    scan_manager = ScanManager(args.scan)
    mode         = determine_mode(args)

    print(f"\n[*] Mode          : {mode}")
    print(f"[*] Target URL    : {args.url or 'N/A'}")
    print(f"[*] Source Dir    : {args.src or 'N/A'}")
    print(f"[*] Active Modules: {', '.join(scan_manager.active_modules())}")
    print(f"[*] AI Provider   : {config.AI_PROVIDER}")
    print(f"[*] Output Dir    : {args.output}")
    print()

    all_findings = []

    # ── Static Phase ──────────────────────────────────────────────────────────
    if mode in ("hybrid", "static") and config.SOURCE_DIR:
        print("[*] Starting Static Analysis...")
        # TODO: from static.scanner import StaticScanner
        # static_findings = StaticScanner(scan_manager).run(config.SOURCE_DIR)
        # all_findings.extend(static_findings)
        print("    [!] Static module not yet implemented — coming soon")

    # ── Dynamic Phase ─────────────────────────────────────────────────────────
    if mode in ("hybrid", "dynamic", "dynamic-only") and config.TARGET_URL:
        print("[*] Starting Dynamic Analysis...")
        from dynamic.crawler import Crawler

        # Auto-detect DVWA and pass credentials
        auth = None
        if 'dvwa' in config.TARGET_URL.lower() or \
           'localhost' in config.TARGET_URL.lower():
            # Extract base dvwa path for login URL
            parsed_target = urlparse(config.TARGET_URL)
            base_path = '/'.join(
                parsed_target.path.rstrip('/').split('/')[:2]
            )  # e.g. /dvwa
            login_url = f"{parsed_target.scheme}://{parsed_target.netloc}{base_path}/login.php"
            auth = {
                'url'            : login_url,
                'username_field' : 'username',
                'password_field' : 'password',
                'username'       : 'admin',
                'password'       : 'password',
                'extra_fields'   : {'Login': 'Login'}
            }

        # Always crawl from index.php so relative links resolve correctly
        crawl_url = config.TARGET_URL.rstrip('/')
        if not crawl_url.endswith('.php'):
            crawl_url = crawl_url + '/index.php'

        crawler   = Crawler(crawl_url, auth=auth)
        endpoints = crawler.crawl()
        print(f"[*] Crawler found {len(endpoints)} endpoint(s) to test.\n")

        # ── SQLi Injector ─────────────────────────────────────────────────────
        if scan_manager.is_active('sqli'):
            from dynamic.sqli_injector import SQLiInjector
            sqli_findings = SQLiInjector(
                crawler.session, scan_manager, auth=auth
            ).run(endpoints)
            all_findings.extend(sqli_findings)

        # ── XSS Injector ──────────────────────────────────────────────────────
        if scan_manager.is_active('xss'):
            from dynamic.xss_injector import XSSInjector
            xss_findings = XSSInjector(
                crawler.session, scan_manager, auth=auth
            ).run(endpoints)
            all_findings.extend(xss_findings)

    # ── Correlation ───────────────────────────────────────────────────────────
    if all_findings:
        print("[*] Running Correlation Engine...")
        # TODO: from core.correlator import correlate
        # all_findings = correlate(all_findings)

    # ── Report ────────────────────────────────────────────────────────────────
    if all_findings:
        print("[*] Generating Report...")
        # TODO: from core.reporter import Reporter
        # Reporter(all_findings, args.output).generate()
    else:
        print("[*] No findings to report yet.")

    print("\n[*] Scan complete.")


if __name__ == "__main__":
    main()