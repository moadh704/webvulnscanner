<div align="center">

# WebVulnScanner

**Hybrid static + dynamic web vulnerability scanner**

*Automatic detection of web application vulnerabilities using a hybrid static-dynamic approach*

[![Version](https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge&logo=semver&logoColor=white)](https://github.com/moadh704/webvulnscanner/releases)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](#install)
[![License](https://img.shields.io/badge/license-Personal%20Use-yellow?style=for-the-badge)](#license)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange?style=for-the-badge)](#supported-checks)

[![Last commit](https://img.shields.io/github/last-commit/moadh704/webvulnscanner?style=flat-square&logo=github)](https://github.com/moadh704/webvulnscanner/commits/main)
[![Interface](https://img.shields.io/badge/interface-CLI%20%7C%20Streamlit-8A2BE2?style=flat-square&logo=streamlit&logoColor=white)](#web-ui)
[![Analysis](https://img.shields.io/badge/analysis-static%20%2B%20dynamic-0ea5e9?style=flat-square)](#how-it-works)
[![AI](https://img.shields.io/badge/AI-Groq%20%7C%20Gemini%20%7C%20OpenRouter%20%7C%20DeepSeek%20%7C%20Ollama-critical?style=flat-square)](#ai-enhancement-optional)

---

**Static analysis** (AST + rules) meets **active dynamic testing** against a
live target. Built for the common OWASP Top 10 issue classes, with an optional
AI layer for false-positive review and remediation notes.

**Ships with** — [semgrep](https://semgrep.dev) rule engine ·
[requests](https://requests.readthedocs.io) · [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) ·
[Streamlit](https://streamlit.io) UI · Zero-cost CLI

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
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

| | | |
|---|---|---|
| **Hybrid analysis** | Static rules (semgrep + AST) fused with a live crawl and payload injection | `full` / `static` / `dynamic` modes |
| **6 vulnerability modules** | SQLi, reflected XSS, command injection, path traversal, IDOR, security misconfiguration | per-module via `--scan` |
| **Verified findings** | Tiered output — static candidates that are *confirmed* against the live target are upgraded | Type 1 / 2 / 3 |
| **Optional AI layer** | False-positive review and remediation notes via Groq, Gemini, OpenRouter (35+ free models), DeepSeek, or local Ollama | opt-in |
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
| <span style="color:#3fb950">**T1**</span> | **Verified** | Static rule matched **and** the live target confirmed it |
| <span style="color:#d29922">**T2**</span> | **Candidate** | Static rule matched; no live confirmation |
| <span style="color:#8b949e">**T3**</span> | **Detected** | Found only by dynamic testing |

## Quick start

**1. Get the code**

```bash
git clone https://github.com/moadh704/webvulnscanner.git
cd webvulnscanner
```

**2. Install**

```bash
# Windows — double-click or run in cmd/powershell
setup.bat                # creates venv, installs deps, installs wvs, copies config.py

# Linux / macOS
bash setup.sh            # same steps for bash

# Or manually on any platform:
pip install -r requirements.txt
pip install -e .         # optional: enables the wvs command
```

On Windows, `run.bat` opens an interactive menu (quick scans, UI launcher, open reports folder).

**3. Scan**

```bash
# Hybrid — analyze source code AND test the live target
wvs --url http://localhost/dvwa --src ./dvwa-source/

# Dynamic only — no source code needed
wvs --url http://localhost/mutillidae --mode dynamic
```

Reports are written to `reports/` (HTML + JSON by default).

## Usage

```bash
# Hybrid (source + live target)
wvs --url http://localhost/dvwa --src ./dvwa-source/

# Static only — no live requests
wvs --url http://localhost/dvwa --mode static --src ./source-code/

# Dynamic only — crawl + inject against a running app
wvs --url http://localhost/dvwa --mode dynamic

# Target specific modules
wvs --url http://localhost/dvwa --scan sqli,xss,cmdi

# Authenticated scan with a DVWA security level
wvs --url http://localhost/dvwa \
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
| `--ai-provider` | `groq` \| `gemini` \| `openrouter` \| `deepseek` \| `deepseek-flash` \| `deepseek-pro` \| `none` | config |
| `--no-ai` | Disable AI layer | AI on if configured |
| `--timeout` | Request timeout (seconds) | config |
| `--max-pages` | Crawl limit | config |
| `--max-response-kb` | Cap response body size in KB (prevent OOM) | 2048 |
| `--allow-subdomains` | Allow crawling subdomains of the target | off |
| `--ai-max-findings` | Cap AI-reviewed findings by severity | 0 (all) |
| `--ai-max-remediations` | Cap AI-generated remediations | 0 (all) |
| `--report-name` | Custom report basename | auto |
| `--verbose` / `--quiet` | Log detail | normal |

Run `wvs --help` for the full list.
</details>

## Web UI

Launch the Streamlit dashboard:

```bash
streamlit run app.py
```

On Windows you can just double-click **`ui.bat`**.

## Sample reports

Real output from a full hybrid scan of a **local DVWA lab** (security level: low):

<span style="color:#ff4444">60 findings</span> ·
<span style="color:#ff4444">13 Critical</span> ·
<span style="color:#ff8c00">25 High</span> ·
<span style="color:#ffce00">19 Medium</span> ·
<span style="color:#58a6ff">3 Low</span>

| Sample | Target | Notes |
|--------|--------|-------|
| [HTML report](docs/examples/sample-report-dvwa.html) | `http://localhost/dvwa` | Full interactive report with severity charts, no AI |
| [Results table](docs/examples/sample-results-dvwa.md) | `http://localhost/dvwa` | Readable findings summary from the same run |
| [JSON](docs/examples/sample-report-dvwa.json) | `http://localhost/dvwa` | Machine-readable, for tooling demos |
| [Full hybrid + free AI](docs/examples/sample-report-dvwa-full-ai.html) | `http://localhost/dvwa` | All 6 modules with live OpenRouter free-tier AI (48 findings, 8 FPs dismissed by AI) |
| [OpenRouter AI](docs/examples/sample-report-dvwa-openrouter.html) | `http://localhost/dvwa` | Hybrid + OpenRouter AI (41 findings, 15 dismissed) — free, no card |
| [bWAPP XSS](docs/examples/sample-report-bwapp-xss.html) | `http://localhost/bWAPP/xss_get.php` | Focused reflected XSS run |

More in [`docs/examples/`](docs/examples/). All samples come from **local lab
targets only** — paths sanitized, no production systems involved.

## Supported checks

| Issue | OWASP area | Static | Dynamic |
|-------|------------|:------:|:-------:|
| SQL injection | A03 – Injection | <span style="color:#3fb950">yes</span> | <span style="color:#3fb950">yes</span> |
| Reflected XSS | A03 – Injection | <span style="color:#3fb950">yes</span> | <span style="color:#3fb950">yes</span> |
| Command injection | A03 – Injection | <span style="color:#3fb950">yes</span> | <span style="color:#3fb950">yes</span> |
| Path traversal | A01 – Broken access | <span style="color:#3fb950">yes</span> | <span style="color:#3fb950">yes</span> |
| IDOR / broken access control | A01 – Broken access | <span style="color:#8b949e">no</span> | <span style="color:#3fb950">yes</span> |
| Security misconfiguration | A05 – Misconfiguration | <span style="color:#8b949e">no</span> | <span style="color:#3fb950">yes</span> |

## Configuration

```bash
cp config.example.py config.py   # or just run wvs once — config.py is created automatically from the example with sensible defaults
```

Edit `config.py` for request timeouts, crawl limits, AI keys, and report paths.
Most settings can also be passed as CLI flags.

## AI enhancement (optional)

Let a language model review the findings, filter false positives, and add
remediation notes:

| Provider | Type | Notes |
|----------|------|-------|
| **Groq** | Cloud | Fast; free tier, 14k req/day |
| **Gemini** | Cloud | Free tier, 1M-token context |
| **OpenRouter** | Cloud | Free, 35+ models via 1 key, 20 RPM, no card |
| **DeepSeek Flash** | Cloud | V4 Flash — fast & cheap, 1M-token context, OpenAI-compatible |
| **DeepSeek Pro** | Cloud | V4 Pro — deeper reasoning for tricky findings |
| **Ollama** | Local | Runs entirely on your machine |

```bash
# Enable a provider
wvs --url http://localhost/dvwa --ai-provider openrouter   # free, no card
wvs --url http://localhost/dvwa --ai-provider groq         # free, 14k/day
wvs --url http://localhost/dvwa --ai-provider deepseek-flash

# Or disable it
wvs --url http://localhost/dvwa --no-ai
```

Set keys in `config.py`:
- `OPENROUTER_API_KEY` at [openrouter.ai/keys](https://openrouter.ai/keys) (free, no card)
- `GROQ_API_KEY` at [console.groq.com](https://console.groq.com)
- `DEEPSEEK_API_KEY` at [platform.deepseek.com](https://platform.deepseek.com/api_keys)
- Plain `deepseek` uses `DEEPSEEK_MODEL` from config (default `deepseek-v4-flash`).

HTML reports now include a filter bar (severity / type / status chips, text search, sort) for triage.

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

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `semgrep` install fails / `semgrep: command not found` | `pip install semgrep --upgrade` — requires Python 3.8+ and a recent pip. On some systems use `pip install semgrep --no-cache` |
| OpenRouter free models return `404` or empty responses | Free catalog rotates weekly. Check live list at https://openrouter.ai/collections/free-models or use `openrouter/free` auto-router (default). Paid `openai/gpt-4o-mini` (~$0.01/scan) is the cheapest reliable fallback |
| `429 free-models-per-day` | Free tier is 50/day (1000/day after $10 credits). Wait 24h, add credits, switch to Groq (`groq` 14k/day), or rerun with `--no-ai` for static remediations |
| `wvs: command not found` after `pip install -e .` | Activate the venv (`venv\Scripts\activate` or `source venv/bin/activate`) or use `wvs.bat` / `python -m main` directly |
| DVWA shows setup page / DB error | Start XAMPP Apache + MySQL and visit `http://localhost/dvwa/setup.php` → Create / Reset Database |

## Disclaimer

> Use **only** on systems you own or have explicit permission to test.
> Unauthorized scanning is illegal in most jurisdictions. The authors assume
> no responsibility for misuse of this tool.

## License

[Personal Use License](LICENSE) — personal, private, non-commercial use only.
No commercial use, no redistribution. See the LICENSE file for the full terms.

---

<div align="center">

*Moadh & Mamon · 2026 — built for the Master's thesis project on hybrid
static-dynamic web vulnerability detection*

</div>
