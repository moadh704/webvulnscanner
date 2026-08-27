#!/usr/bin/env python
"""End-to-end tests: run the real CLI from start to finish.

Scenario 1 (always): static-only scan of a small intentionally-vulnerable
PHP fixture - asserts the static engine finds sqli + xss and writes both
report formats. CI-safe, no network needed.

Scenario 2 (auto-detect): full hybrid scan against a local DVWA when it
is reachable - asserts crawl, injection, correlation (Type 1 findings),
and report generation all work. Skipped silently in CI.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, 'fixtures', 'vuln_app')
DVWA_SRC = r'C:\xampp\htdocs\dvwa'
DVWA_URL = 'http://localhost/dvwa'


def _run_scan(args, timeout=600):
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, 'main.py')] + args,
        capture_output=True, text=True, encoding='utf-8',
        errors='replace', env=env, timeout=timeout,
    )


def _load_report(out_dir, name):
    with open(os.path.join(out_dir, name + '.json'), encoding='utf-8') as fh:
        return json.load(fh)


def test_static_fixture_scan():
    """Static scan of the vulnerable fixture must find sqli + xss and
    write both report formats."""
    out_dir = tempfile.mkdtemp(prefix='wvs_e2e_')
    try:
        proc = _run_scan([
            '--src', FIXTURE, '--mode', 'static', '--no-ai',
            '--output', out_dir, '--report-name', 'e2e_static',
        ], timeout=300)
        assert proc.returncode == 0, (
            f'exit {proc.returncode}: {proc.stdout[-800:]}')
        data = _load_report(out_dir, 'e2e_static')
        findings = data.get('findings', [])
        types = {f.get('type') for f in findings}
        assert 'sqli' in types, f'no sqli finding; got {sorted(types)}'
        assert 'xss' in types, f'no xss finding; got {sorted(types)}'
        assert os.path.isfile(os.path.join(out_dir, 'e2e_static.html'))
        print(f'  static fixture: {len(findings)} findings '
              f'({sorted(types)})')
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def test_hybrid_dvwa_scan():
    """Full hybrid scan against local DVWA when available (skipped in CI)."""
    if not os.path.isdir(DVWA_SRC):
        print('  hybrid: skipped (DVWA source not present)')
        return
    try:
        r = requests.get(DVWA_URL + '/login.php', timeout=5)
        if r.status_code != 200 or 'password' not in r.text:
            print('  hybrid: skipped (DVWA not reachable)')
            return
    except requests.RequestException:
        print('  hybrid: skipped (DVWA not reachable)')
        return

    out_dir = tempfile.mkdtemp(prefix='wvs_e2e_')
    try:
        proc = _run_scan([
            '--url', DVWA_URL, '--src', DVWA_SRC,
            '--username', 'admin', '--password', 'password',
            '--difficulty', 'low', '--no-ai', '--max-pages', '50',
            '--output', out_dir, '--report-name', 'e2e_hybrid',
        ], timeout=600)
        assert proc.returncode == 0, (
            f'exit {proc.returncode}: {proc.stdout[-800:]}')
        data = _load_report(out_dir, 'e2e_hybrid')
        findings = data.get('findings', [])
        summary = data.get('scan_info', {}).get('summary', {})
        assert len(findings) >= 20, (
            f'expected >=20 findings, got {len(findings)}')
        assert summary.get('type1', 0) >= 1, (
            f'expected verified findings, got {summary}')
        assert os.path.isfile(os.path.join(out_dir, 'e2e_hybrid.html'))
        print(f'  hybrid DVWA: {len(findings)} findings, '
              f'{summary.get("type1", 0)} verified')
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == '__main__':
    t0 = time.time()
    test_static_fixture_scan()
    test_hybrid_dvwa_scan()
    print(f'ALL PASS ({time.time() - t0:.0f}s)')
