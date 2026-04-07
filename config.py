# ── WebVulnScanner Configuration ─────────────────────────────────────────────

# ── Target (set via CLI, do not change here) ──────────────────────────────────
TARGET_URL  = ""
SOURCE_DIR  = ""

# ── Request settings ──────────────────────────────────────────────────────────
REQUEST_TIMEOUT   = 10       # seconds per HTTP request
TIME_BASED_DELAY  = 4        # seconds threshold for time-based SQLi/CMDi
MAX_CRAWL_PAGES   = 50       # max pages the crawler will visit
REQUEST_HEADERS   = {
    "User-Agent": "WebVulnScanner/1.0 (Academic Security Research)"
}

# ── AI Enhancement Layer ──────────────────────────────────────────────────────
# Options: "gemini" (default, free) | "ollama" (offline) | "none" (disabled)
AI_PROVIDER    = "none"      # set to "gemini" when you have an API key

GEMINI_API_KEY = "your_key_here"   # free at aistudio.google.com
OLLAMA_MODEL   = "codellama"       # only used if AI_PROVIDER = "ollama"
OLLAMA_URL     = "http://localhost:11434/api/generate"

# ── Report settings ───────────────────────────────────────────────────────────
REPORT_OUTPUT_DIR = "reports"
