# WebVulnScanner — Sample Scan Results (DVWA, security level: low)

Sample run of the **full hybrid** mode against a local [DVWA](https://github.com/digininja/DVWA) instance (deliberately vulnerable, for testing only).

> Live report: [`dvwa-sample-report.html`](dvwa-sample-report.html) (charts require internet for Chart.js from CDN).

## Summary

| Metric | Value |
|---|---|
| Target | `http://localhost/dvwa` |
| Mode | full (hybrid static + dynamic) |
| Difficulty | low |
| Findings | 60 |
| Severities | Critical: 13, High: 25, Medium: 19, Low: 3 |
| Tier 1 — static confirmed by dynamic (Verified) | 5 |
| Tier 2 — static only (Candidate) | 43 |
| Tier 3 — dynamic only (Detected) | 12 |

## Findings

| # | Type | Severity | Tier | Technique | URL |
|---|---|---|---|---|---|
| 1 | cmdi | Critical | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\exec\source\impossible.php` |
| 2 | cmdi | Critical | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\exec\source\medium.php` |
| 3 | cmdi | Critical | T1 | output-based | `http://localhost/dvwa/vulnerabilities/exec/` |
| 4 | idor | Critical | T3 | sequential-enumeration | `http://localhost/dvwa/vulnerabilities/open_redirect/source/info.php?id=1` |
| 5 | idor | Critical | T3 | sequential-enumeration | `http://localhost/dvwa/vulnerabilities/open_redirect/source/info.php?id=2` |
| 6 | sqli | Critical | T1 | error-based | `http://localhost/dvwa/vulnerabilities/sqli/` |
| 7 | sqli | Critical | T1 | time-based | `http://localhost/dvwa/vulnerabilities/sqli_blind/` |
| 8 | traversal | Critical | T3 | path-traversal | `http://localhost/dvwa/vulnerabilities/fi/?page=file1.php` |
| 9 | traversal | Critical | T3 | path-traversal | `http://localhost/dvwa/vulnerabilities/fi/?page=file2.php` |
| 10 | traversal | Critical | T3 | path-traversal | `http://localhost/dvwa/vulnerabilities/fi/?page=file3.php` |
| 11 | traversal | Critical | T3 | path-traversal | `http://localhost/dvwa/vulnerabilities/fi/?page=include.php` |
| 12 | xss | Critical | T1 | reflected | `http://localhost/dvwa/vulnerabilities/csp/` |
| 13 | xss | Critical | T1 | reflected | `http://localhost/dvwa/vulnerabilities/xss_r/` |
| 14 | headers | High | T3 | header-inspection | `http://localhost` |
| 15 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\login.php` |
| 16 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\login.php` |
| 17 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\bac\source\medium.php` |
| 18 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\high.php` |
| 19 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\high.php` |
| 20 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\low.php` |
| 21 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\low.php` |
| 22 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\medium.php` |
| 23 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\medium.php` |
| 24 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\captcha\source\high.php` |
| 25 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\captcha\source\high.php` |
| 26 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\captcha\source\low.php` |
| 27 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\captcha\source\low.php` |
| 28 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\captcha\source\medium.php` |
| 29 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\captcha\source\medium.php` |
| 30 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\source\low.php` |
| 31 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\source\low.php` |
| 32 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\source\medium.php` |
| 33 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\source\medium.php` |
| 34 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\test_credentials.php` |
| 35 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\test_credentials.php` |
| 36 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\sqli\source\medium.php` |
| 37 | sqli | High | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\sqli_blind\source\medium.php` |
| 38 | xss | High | T3 | reflected | `http://localhost/dvwa/vulnerabilities/xss_s/` |
| 39 | headers | Medium | T3 | header-inspection | `http://localhost` |
| 40 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\instructions.php` |
| 41 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\login.php` |
| 42 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\login.php` |
| 43 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\bac\source\medium.php` |
| 44 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\high.php` |
| 45 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\high.php` |
| 46 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\low.php` |
| 47 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\low.php` |
| 48 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\medium.php` |
| 49 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\brute\source\medium.php` |
| 50 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csp\source\high.php` |
| 51 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csp\source\impossible.php` |
| 52 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csp\source\medium.php` |
| 53 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\test_credentials.php` |
| 54 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\csrf\test_credentials.php` |
| 55 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\sqli\source\medium.php` |
| 56 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\sqli_blind\source\low.php` |
| 57 | xss | Medium | T2 | - | `C:\xampp\htdocs\dvwa\vulnerabilities\sqli_blind\source\medium.php` |
| 58 | headers | Low | T3 | header-inspection | `http://localhost` |
| 59 | headers | Low | T3 | header-inspection | `http://localhost` |
| 60 | headers | Low | T3 | header-inspection | `http://localhost` |

## Reproduce

```bash
wvs --url http://localhost/dvwa \
  --src C:\xampp\htdocs\dvwa --mode full --no-ai --difficulty low
```
