# ── WebVulnScanner Configuration ─────────────────────────────────────────────
# Copy this file to config.py and fill in your values

# ── Target (set via CLI, do not change here) ──────────────────────────────────
TARGET_URL  = ""
SOURCE_DIR  = ""

# ── Request settings ──────────────────────────────────────────────────────────
REQUEST_TIMEOUT   = 10
TIME_BASED_DELAY  = 4
MAX_CRAWL_PAGES   = 50
REQUEST_HEADERS   = {
    "User-Agent": "WebVulnScanner/1.0 (Academic Security Research)"
}

# Allow crawling subdomains of the target host (e.g. api.example.com when
# scanning app.example.com). Off by default — scope is limited to the
# exact host, so a linked sibling domain is never attacked.
ALLOW_SUBDOMAINS = False

# ── AI Enhancement Layer ──────────────────────────────────────────────────────
# Options: "groq" (free, recommended) | "gemini" (free tier) | "deepseek" |
#          "ollama" (local) | "none"
AI_PROVIDER    = "none"

GEMINI_API_KEY = ""   # free at aistudio.google.com
GROQ_API_KEY   = ""   # free at console.groq.com
DEEPSEEK_API_KEY = "" # at platform.deepseek.com
DEEPSEEK_MODEL   = "deepseek-v4-flash"
OLLAMA_MODEL   = "codellama"
OLLAMA_URL     = "http://localhost:11434/api/generate"

# ── AI cost controls ──────────────────────────────────────────────────────────
AI_REMEDIATION  = True   # generate AI remediation text (extra API calls);
                         # False = static OWASP text instead
AI_MAX_FINDINGS = 0      # cap AI-reviewed findings by severity
                         # (0 = review all; e.g. 20 = top 20 most severe)

# ── Report settings ───────────────────────────────────────────────────────────
REPORT_OUTPUT_DIR = "reports"
