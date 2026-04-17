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

# ── AI Enhancement Layer ──────────────────────────────────────────────────────
# Options: "groq" (free, recommended) | "gemini" (free tier) | "none"
AI_PROVIDER    = "none"

GEMINI_API_KEY = ""   # free at aistudio.google.com
GROQ_API_KEY   = ""   # free at console.groq.com
OLLAMA_MODEL   = "codellama"
OLLAMA_URL     = "http://localhost:11434/api/generate"

# ── Report settings ───────────────────────────────────────────────────────────
REPORT_OUTPUT_DIR = "reports"
