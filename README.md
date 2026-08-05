# WebVulnScanner

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/OWASP-Top%2010-orange?style=for-the-badge" alt="OWASP" />
</p>

<p align="center">
  <a href="https://github.com/moadh704/webvulnscanner/issues">
    <img src="https://img.shields.io/github/issues/moadh704/webvulnscanner?style=flat-square" alt="Issues" />
  </a>
  <img src="https://img.shields.io/github/last-commit/moadh704/webvulnscanner?style=flat-square" alt="Last commit" />
  <img src="https://img.shields.io/github/languages/top/moadh704/webvulnscanner?style=flat-square" alt="Top language" />
  <img src="https://img.shields.io/badge/interface-CLI%20%7C%20Streamlit-8A2BE2?style=flat-square" alt="Interface" />
  <img src="https://img.shields.io/badge/analysis-static%20%2B%20dynamic-0ea5e9?style=flat-square" alt="Analysis" />
  <img src="https://img.shields.io/badge/AI-Groq%20%7C%20Gemini%20%7C%20Ollama-critical?style=flat-square" alt="AI providers" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SQLi-supported-success?style=flat-square" alt="SQLi" />
  <img src="https://img.shields.io/badge/XSS-supported-success?style=flat-square" alt="XSS" />
  <img src="https://img.shields.io/badge/CMDi-supported-success?style=flat-square" alt="CMDi" />
  <img src="https://img.shields.io/badge/Path%20Traversal-supported-success?style=flat-square" alt="Traversal" />
  <img src="https://img.shields.io/badge/IDOR-supported-success?style=flat-square" alt="IDOR" />
  <img src="https://img.shields.io/badge/Misconfig-supported-success?style=flat-square" alt="Misconfig" />
</p>

Hybrid static + dynamic web vulnerability scanner (Master’s graduation project).  
Analyzes source code and runs active tests against a live target. Aligns with common OWASP Top 10 issue classes.

CLI and Streamlit UI. Optional AI step for false-positive review and remediation notes (Groq, Gemini, or Ollama).

## Features

- Static (AST/rules) and dynamic (crawl + inject) analysis
- Modules: SQLi, reflected XSS, command injection, path traversal, IDOR, security misconfiguration
- Finding tiers: Verified (Type 1), Candidate (Type 2), Detected (Type 3)
- Modes: `full` (hybrid), `static`, `dynamic`
- Selective modules via `--scan`
- Optional AI enhancement (false-positive review + remediation)
- HTML and JSON reports
- Rich CLI + Streamlit UI
- Windows setup scripts (`setup.bat`, `ui.bat`)

## Install

Windows:

```bash
git clone https://github.com/moadh704/webvulnscanner.git
cd webvulnscanner
setup.bat
```

Manual:

```bash
git clone https://github.com/moadh704/webvulnscanner.git
cd webvulnscanner
pip install -r requirements.txt
# optional package entry point:
pip install -e .
```

## Quick start

Hybrid (source + live target):

```bash
WebVulnScanner --url http://localhost/dvwa --src ./dvwa-source/
```

Dynamic only (no source):

```bash
WebVulnScanner --url http://localhost/mutillidae --mode dynamic
```

Reports go to `reports/` (HTML + JSON by default).

You can also run via:

```bash
python main.py --url http://localhost/dvwa --mode dynamic
```

## Configuration

```bash
cp config.example.py config.py
```

Edit `config.py` for timeouts, crawl limits, AI keys, and report paths. Most of this can also be set with CLI flags.

## AI enhancement (optional)

| Provider | Notes |
|----------|--------|
| Groq | Cloud; free tier available |
| Gemini | Cloud; free tier available |
| Ollama | Local |

Set keys in `config.py`, or:

```bash
WebVulnScanner --url http://localhost/dvwa --ai-provider groq
WebVulnScanner --url http://localhost/dvwa --no-ai
```

## Usage

```bash
# Hybrid
WebVulnScanner --url http://localhost/dvwa --src ./dvwa-source/

# Dynamic only
WebVulnScanner --url http://localhost/dvwa --mode dynamic

# Static only
WebVulnScanner --url http://localhost/dvwa --mode static --src ./source-code/

# Specific modules
WebVulnScanner --url http://localhost/dvwa --scan sqli,xss,cmdi

# Auth + DVWA difficulty
WebVulnScanner --url http://localhost/dvwa --username admin --password password --difficulty low
```

### Main options

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

`WebVulnScanner --help` lists everything.

### Web UI

Windows: double-click `ui.bat`, or:

```bash
streamlit run app.py
```

## Project layout

```text
webvulnscanner/
├── core/           # engine, correlation, reporting
├── dynamic/        # crawler + injectors
├── static/         # AST analysis + rules
├── templates/      # HTML report template
├── payloads/       # injection payloads
├── app.py          # Streamlit UI
├── main.py         # CLI
└── requirements.txt
```

## Supported checks

| Issue | OWASP area | Method |
|-------|------------|--------|
| SQL injection | Injection | Static + dynamic |
| Reflected XSS | Injection | Static + dynamic |
| Command injection | Injection | Static + dynamic |
| Path traversal | Broken access / path issues | Static + dynamic |
| IDOR / broken access control | Broken access control | Dynamic |
| Security misconfiguration | Misconfiguration | Dynamic |

## Thesis

Built for a Master’s thesis:

> Automatic Detection of Web Application Vulnerabilities Using a Hybrid Static-Dynamic Approach

Authors: Moadh and Mamon · 2026

## Disclaimer

Authorized testing and research only. Use only on systems you own or have permission to test.

## License

MIT
