# Changelog

All notable changes to WebVulnScanner will be documented in this file.

## [1.0.0] - 2026-08-24

### Added
- Hybrid static + dynamic web vulnerability scanner for OWASP Top 10 issue classes.
- Six detection modules: SQL injection, reflected XSS, command injection, path traversal, IDOR, and security headers.
- Three finding tiers: Verified (T1), Candidate (T2), and Detected (T3).
- Static analysis engine powered by Semgrep rules.
- Dynamic crawler with login auto-detection, DVWA security-level setter, and exact-host scope (subdomain opt-in).
- Optional AI enhancement layer supporting Groq, Gemini, OpenRouter, DeepSeek, DeepSeek Flash/Pro, and local Ollama.
- AI pre-flight health check to skip wasted calls when a provider is unreachable or rate-limited.
- Language-aware remediation prompts (PHP, Python, Node.js, Java, Go, Ruby, C#).
- Structured JSON batch verdicts with legacy text fallback.
- Dedicated `ai_error` field so provider errors don't pollute AI notes or remediations.
- Interactive HTML reports with filter bar (severity / type / status chips), search, sort, and Chart.js visualizations.
- Streamlit web UI for point-and-click scanning, live logs, triage, history, and report downloads.
- Windows helpers: `setup.bat`, `ui.bat`, `run.bat`, `wvs.bat`.
- Linux / macOS helper: `setup.sh`.
- Sample lab reports for DVWA and bWAPP in `docs/examples/`.

### Fixed
- Iterative crawler queue prevents recursion-depth crashes on large sites.
- Response size cap prevents OOM on huge responses.
- AI call counting now includes remediation calls and respects `AI_MAX_REMEDIATIONS`.
- `main.py` top-level exception handling writes partial reports on crashes.
- `AI_PROVIDER=None` or empty no longer crashes the scanner.
- General provider error handling with circuit breaker for rate limits, bad keys, and model unavailability.
- Friendly provider error messages instead of raw `REAL (Provider error: ...)` strings.
- Streamlit scan launch fixed for paths containing spaces or `&`.
- UI evidence language no longer hardcoded to PHP.
- Misleading "Print to PDF" button removed.
- Advanced UI controls wired to real CLI flags: `--allow-subdomains`, `--max-response-kb`, `--ai-max-findings`, `--ai-max-remediations`.

### Security
- Prompt-injection guard wraps target-derived evidence in fenced blocks.
- Empty and error AI responses are never cached to avoid poisoning future scans.
- Exact-host crawling scope prevents sibling-subdomain attacks by default.
