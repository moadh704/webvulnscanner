# WebVulnScanner

**WebVulnScanner** is a lightweight hybrid static and dynamic web vulnerability scanner developed as part of a Master's graduation project. It combines source code analysis with active runtime testing to detect common web vulnerabilities aligned with the **OWASP Top 10 (2025)**.

The tool supports both command-line and web-based interfaces and includes an optional AI Enhancement Layer for false positive reduction and remediation guidance.

## ✨ Features

- **Hybrid Analysis**: Combines static (AST-based) and dynamic (active injection) detection
- **Six Vulnerability Modules**: SQL Injection, Reflected XSS, Command Injection, Path Traversal, IDOR, and Security Misconfiguration
- **Three-Tier Classification**: Verified (Type 1), Candidate (Type 2), Detected (Type 3)
- **Selective Scanning**: Run only specific modules using `--scan`
- **Dual Operating Modes**: Hybrid (with source code) + Dynamic-only (black-box)
- **AI Enhancement Layer**: Optional false-positive review + context-aware remediation (Groq, Gemini, Ollama)
- **Professional Reporting**: HTML reports with charts + JSON export
- **User Interfaces**: Rich CLI + Streamlit web UI
- **Easy Deployment**: One-click setup scripts for Windows

## 🚀 Installation

### Quick Setup (Windows)
```bash
git clone https://github.com/moadh704/webvulnscanner.git
cd webvulnscanner
setup.bat
```

### Manual Installation
```bash
git clone https://github.com/moadh704/webvulnscanner.git
cd webvulnscanner
pip install -r requirements.txt
```

## 🚀 Quick Start

### 1. Basic Hybrid Scan (Recommended)
```bash
WebVulnScanner --url http://localhost/dvwa --src ./dvwa-source/
```

### 2. Dynamic-only Scan (No source code needed)
```bash
WebVulnScanner --url http://localhost/mutillidae --mode dynamic
```

Reports are saved in the `reports/` folder as HTML files.

## ⚙️ Configuration

WebVulnScanner supports a `config.py` file for advanced settings.

1. Copy the example configuration:
   ```bash
   cp config.example.py config.py
   ```

2. Edit `config.py` to customize:
   - Request timeout and delays
   - Maximum pages to crawl
   - AI provider and API keys
   - Report output directory

> Most settings can also be overridden using command-line flags.

## 🤖 AI Enhancement Setup (Optional)

The AI layer can significantly reduce false positives and provide remediation suggestions.

### Supported AI Providers

| Provider   | Type     | Free Tier | Recommendation |
|------------|----------|-----------|----------------|
| **Groq**   | Cloud    | Yes       | ★★★★★ (Recommended) |
| **Gemini** | Cloud    | Yes       | ★★★★       |
| **Ollama** | Local    | Yes       | ★★★         |

### How to Enable

1. Get an API key:
   - **Groq**: [console.groq.com](https://console.groq.com)
   - **Gemini**: [aistudio.google.com](https://aistudio.google.com)

2. Add the key in `config.py` or use the flag:
   ```bash
   WebVulnScanner --ai-provider groq
   ```

## 📊 Reports & Output

After scanning, WebVulnScanner generates:

- **HTML Report** with charts and detailed findings (saved in `reports/`)
- **JSON export** for further processing

You can open the HTML report directly in your browser.

## ▶️ Usage

### Command-Line Interface

WebVulnScanner is installed as a console command. The recommended way to run it is:

```bash
WebVulnScanner [options]
```

#### Basic Usage Examples

```bash
# Full hybrid scan (static + dynamic) - recommended for most cases
WebVulnScanner --url http://localhost/dvwa --src ./dvwa-source/

# Dynamic-only (black-box) scan
WebVulnScanner --url http://localhost/dvwa --mode dynamic

# Static-only analysis
WebVulnScanner --url http://localhost/dvwa --mode static --src ./source-code/

# Run only specific vulnerability modules
WebVulnScanner --url http://localhost/dvwa --scan sqli,xss,cmdi

# Disable AI enhancement layer
WebVulnScanner --url http://localhost/dvwa --no-ai

# Use a specific AI provider for analysis
WebVulnScanner --url http://localhost/dvwa --ai-provider groq

# Authenticated scan with credentials
WebVulnScanner --url http://localhost/dvwa --username admin --password password
```

#### Common Command-Line Options

| Option              | Description                                                                 | Default     |
|---------------------|-----------------------------------------------------------------------------|-------------|
| `--url`             | Target web application URL (required)                                       | —           |
| `--src`             | Path to the source code directory (enables hybrid/static analysis)          | —           |
| `--scan`            | Comma-separated list of modules to enable (e.g. `sqli,xss,cmdi`)            | all         |
| `--mode`            | Scan mode: `full` (hybrid), `static`, or `dynamic`                          | `full`      |
| `--no-ai`           | Disable the AI Enhancement Layer                                            | enabled     |
| `--ai-provider`     | AI provider to use for analysis (`groq`, `gemini`, or `none`)               | —           |
| `--username`        | Username for authenticated scanning                                         | —           |
| `--password`        | Password for authenticated scanning                                         | —           |
| `--difficulty`      | Set application difficulty level (e.g. for DVWA)                            | —           |

> **Tip:** Run `WebVulnScanner --help` to see the complete list of available options.

### Web Interface

WebVulnScanner includes a modern Streamlit-based web interface for easier configuration and result visualization.

**Recommended for Windows users:**
- Simply double-click the `ui.bat` file in the project root directory.

**Alternative (cross-platform):**
```bash
streamlit run app.py
```

The web interface allows you to configure scans, monitor progress, and view detailed HTML reports directly in your browser.

## 📁 Project Structure

```
webvulnscanner/
├── core/           # Core engine, correlation, reporting
├── dynamic/        # Crawler + all injectors
├── static/         # AST-based static analysis + YAML rules
├── templates/      # HTML report template
├── payloads/       # Injection payloads
├── app.py          # Streamlit web interface
├── main.py         # CLI entry point
└── requirements.txt
```

## 🔍 Supported Vulnerabilities (OWASP Top 10 2025)

| Vulnerability                  | OWASP Category          | Detection Method     |
|--------------------------------|-------------------------|----------------------|
| SQL Injection                  | A05 - Injection         | Static + Dynamic     |
| Reflected XSS                  | A05 - Injection         | Static + Dynamic     |
| Command Injection              | A05 - Injection         | Static + Dynamic     |
| Path Traversal                 | A01                     | Static + Dynamic     |
| IDOR / Broken Access Control   | A01                     | Dynamic only         |
| Security Misconfiguration      | A02                     | Dynamic only         |

## 📘 Thesis Information

This tool was developed as part of a Master's thesis:

> **Automatic Detection of Web Application Vulnerabilities Using a Hybrid Static-Dynamic Approach**

**Author**: Moadh and mamon  
**Year**: 2026

## 📄 License

This project is licensed under the MIT License.
