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

## ▶️ Usage

### Command Line
```bash
# Hybrid scan (recommended)
python main.py --url http://target.com --src ./source-code/
# Dynamic-only scan
python main.py --url http://target.com
# Run specific modules only
python main.py --url http://target.com --scan sqli,xss
# Disable AI
python main.py --url http://target.com --no-ai
```

### Streamlit Web Interface
```bash
streamlit run app.py
```
Or double-click `ui.bat` on Windows.

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
