<div align="center">

# WebVulnScanner

### Hybrid static + dynamic web vulnerability scanner

*Master's graduation project — Automatic detection of web application
vulnerabilities using a hybrid static-dynamic approach*

[![Version](https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge&logo=semver&logoColor=white)](https://github.com/moadh704/webvulnscanner/releases)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](#install)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](#license)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange?style=for-the-badge)](#supported-checks)

[![GitHub release](https://img.shields.io/github/v/release/moadh704/webvulnscanner?style=flat-square&logo=github)](https://github.com/moadh704/webvulnscanner/releases)
[![Stars](https://img.shields.io/github/stars/moadh704/webvulnscanner?style=flat-square&logo=github&color=gold)](https://github.com/moadh704/webvulnscanner/stargazers)
[![Forks](https://img.shields.io/github/forks/moadh704/webvulnscanner?style=flat-square&logo=github)](https://github.com/moadh704/webvulnscanner/network/members)
[![Issues](https://img.shields.io/github/issues/moadh704/webvulnscanner?style=flat-square&logo=github)](https://github.com/moadh704/webvulnscanner/issues)
[![Last commit](https://img.shields.io/github/last-commit/moadh704/webvulnscanner?style=flat-square&logo=github)](https://github.com/moadh704/webvulnscanner/commits/main)

**Static analysis** (AST + rules) meets **active dynamic testing** against a
live target. Built for the common OWASP Top 10 issue classes, with an optional
AI layer for false-positive review and remediation notes.

</div>

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Finding tiers](#finding-tiers)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Web UI](#web-ui)
- [Sample reports](#sample-reports)
- [Supported checks](#supported-checks)
- [Configuration](#configuration)
- [AI enhancement](#ai-enhancement-optional)
- [Project layout](#project-layout)
- [Thesis](#thesis)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

| | | |
|---|---|---|
| **Hybrid analysis** | Static rules (semgrep + AST) fused with a live crawl and payload injection | `full` / `static` / `dynamic` modes |
| **6 vulnerability modules** | SQLi, reflected XSS, command injection, path traversal, IDOR, security misconfiguration | per-module via `--scan` |
| **Verified findings** | Tiered output — static candidates that are *confirmed* against the live target are upgraded | Type 1 / 2 / 3 |
| **Optional AI layer** | False-positive review and remediation notes via Groq, Gemini, or local Ollama | opt-in |
| **Rich reports** | Interactive HTML (charts) + machine-readable JSON | `reports/` |
| **Two interfaces** | CLI for scripting, Streamlit web UI for point-and-click | `main.py` / `app.py` |
| **One-command setup** | Windows `setup.bat` + `ui.bat` helpers | batteries included |

## How it works

```text
Source code                Live target
     │                         │
     ▼                         ▼
┌──────────┐             ┌──────────┐
│  Static  │             │ Dynamic  │
│  scanner │             │  crawler │
│ (semgrep │             │  (auth,  │
│  rules)  │             │  crawl)  │
└────┬─────┘             └────┬─────┘
     │                        │
     ▼                        ▼
  candidates             endpoints
     │                        │
     └───────────┬────────────┘
                 ▼
        ┌────────────────┐
        │   Correlator   │  static + dynamic
        │  (path match,  │  fused into one
        │   severity)    │  report
        └───────┬────────┘
                ▼
   ┌──────────────────────┐
   │   HTML + JSON report │
   └──────────────────────┘
```

## Finding tiers

Every finding is labeled so you know *how much evidence* backs it:

| Tier | Label | Meaning |
|------|-------|---------|
| **T1** | Verified | Static rule matched **and** the live target confirmed it |
| **T2** | Candidate | Static rule matched; no live confirmation |
| **T3** | Detected | Found only by dynamic testing |

## Quick start

```bash
# Clone + install (Windows)
git clone https://github.com/moadh704/webvulnscanner.git
cd webvulnscanner
setup.bat

# Hybrid scan: analyze source AND test the live target
WebVulnScanner --url http://localhost/dvwa --src ./dvwa-source/

# Dynamic only (no source code available)
WebVulnScanner --url http://localhost/mutillidae --mode dynamic
```

Reports are written to `reports/` (HTML + JSON by default).

## Usage

```bash
# Hybrid (source + live target)
WebVulnScanner --url http://localhost/dvwa --src ./dvwa-source/

# Static only — no live requests
WebVulnScanner --url http://localhost/dvwa --mode static --src ./source-code/

# Dynamic only — crawl + inject against a running app
WebVulnScanner --url http://localhost/dvwa --mode dynamic

# Target specific modules
WebVulnScanner --url http://localhost/dvwa --scan sqli,xss,cmdi

# Authenticated scan with a DVWA security level
WebVulnScanner --url http://localhost/dvwa \
  --username admin --password password --difficulty low
```

<details>
<summary><b>All CLI options</b></summary>

| Option | Description | Default |
|--------|-------------|---------|
| `--url` | Target URL | required for dynamic/full |
| `--src` | Source directory (static/hybrid) | — |
| `--scan` | Modules: `sqli,xss,cmdi,traversal,idor,headers` | all |
| `--mode` | `full` \| `static` \| `dynamic` | `full` |
| `--output` | Report directory | `reports` |
| `--output-format` | `html` \| `json` \| `both` | `both` |
| `--username` / `--password` | Login for authenticated scans | — |
| `--difficulty` | DVWA level: `low`–`impossible` | — |
| `--ai-provider` | `groq` \| `gemini` \| `none` | config |
| `--no-ai` | Disable AI layer | AI on if configured |
| `--timeout` | Request timeout (seconds) | config |
| `--max-pages` | Crawl limit | config |
| `--report-name` | Custom report basename | auto |
| `--verbose` / `--quiet` | Log detail | normal |

Run `WebVulnScanner --help` for the full list.
</details>

## Web UI

Launch the Streamlit dashboard:

```bash
streamlit run app.py
```

On Windows you can just double-click **`ui.bat`**.

## Sample reports

Real output from a full hybrid scan of a **local DVWA lab** (security level: low):

| Sample | Target | Notes |
|--------|--------|-------|
| [HTML report](docs/examples/sample-report-dvwa.html) | `http://localhost/dvwa` | Full interactive report — **60 findings** (13 Critical / 25 High / 19 Medium / 3 Low), no AI |
| [Results table](docs/examples/sample-results-dvwa.md) | `http://localhost/dvwa` | Readable findings summary from the same run |
| [JSON](docs/examples/sample-report-dvwa.json) | `http://localhost/dvwa` | Machine-readable, for tooling demos |
| [bWAPP XSS](docs/examples/sample-report-bwapp-xss.html) | `http://localhost/bWAPP/xss_get.php` | Focused reflected XSS run |

More in [`docs/examples/`](docs/examples/). All samples come from **local lab
targets only** — paths sanitized, no production systems involved.

## Supported checks

| Issue | OWASP area | Static | Dynamic |
|-------|------------|:------:|:-------:|
| SQL injection | A03 – Injection | yes | yes |
| Reflected XSS | A03 – Injection | yes | yes |
| Command injection | A03 – Injection | yes | yes |
| Path traversal | A01 – Broken access | yes | yes |
| IDOR / broken access control | A01 – Broken access | — | yes |
| Security misconfiguration | A05 – Misconfiguration | — | yes |

## Configuration

```bash
cp config.example.py config.py
```

Edit `config.py` for request timeouts, crawl limits, AI keys, and report paths.
Most settings can also be passed as CLI flags.

## AI enhancement (optional)

Let a language model review the findings, filter false positives, and add
remediation notes:

| Provider | Type | Notes |
|----------|------|-------|
| **Groq** | Cloud | Fast; free tier available |
| **Gemini** | Cloud | Free tier available |
| **Ollama** | Local | Runs entirely on your machine |

```bash
# Enable a provider
WebVulnScanner --url http://localhost/dvwa --ai-provider groq

# Or disable it
WebVulnScanner --url http://localhost/dvwa --no-ai
```

## Project layout

```text
webvulnscanner/
├── core/           # engine, correlation, reporting
├── dynamic/        # crawler + injectors
├── static/         # AST analysis + semgrep rules
├── templates/      # HTML report template
├── payloads/       # injection payloads
├── docs/examples/  # sample HTML/JSON reports (lab targets)
├── app.py          # Streamlit UI
├── main.py         # CLI entry point
└── requirements.txt
```

## Thesis

Built as a Master's thesis project:

> **Automatic Detection of Web Application Vulnerabilities Using a Hybrid
> Static-Dynamic Approach**

*Moadh & Mamon · 2026*

## Disclaimer

> Use **only** on systems you own or have explicit permission to test.
> Unauthorized scanning is illegal in most jurisdictions. The authors assume
> no responsibility for misuse of this tool.

## License

[MIT](LICENSE) — free to use, modify, and distribute.