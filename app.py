"""
WebVulnScanner — Streamlit Web UI
Run with: streamlit run app.py
"""

import streamlit as st
import subprocess
import json
import os
import sys
import shutil
import re
import time
from datetime import datetime
from pathlib import Path
import html

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebVulnScanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS — Premium Dark Theme ────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap');

    .stApp {
        background: radial-gradient(ellipse at top, #1a2332 0%, #0d1117 50%, #010409 100%);
        font-family: 'Inter', sans-serif;
    }

    /* ── Header ── */
    .hero {
        background: linear-gradient(135deg, rgba(88,166,255,0.15) 0%, rgba(188,140,255,0.1) 50%, rgba(57,211,83,0.1) 100%);
        border: 1px solid rgba(88,166,255,0.2);
        border-radius: 16px;
        padding: 32px 36px;
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(12px);
    }
    .hero::before {
        content: '';
        position: absolute;
        top: -50%;
        right: -20%;
        width: 400px;
        height: 400px;
        background: radial-gradient(circle, rgba(88,166,255,0.08) 0%, transparent 70%);
        pointer-events: none;
    }
    .hero h1 {
        color: #58a6ff;
        margin: 0;
        font-size: 32px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    .hero h1 span { color: #bc8cff; }
    .hero p {
        color: #8b949e;
        margin: 6px 0 0 0;
        font-size: 14px;
    }
    .hero-badge {
        display: inline-block;
        background: rgba(57,211,83,0.12);
        border: 1px solid rgba(57,211,83,0.3);
        color: #3fb950;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        margin-top: 10px;
        letter-spacing: 0.5px;
    }

    /* ── Metric cards ── */
    .metric-card {
        background: linear-gradient(145deg, #161b22 0%, #1c2128 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 18px 14px;
        text-align: center;
        transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
        position: relative;
        overflow: hidden;
    }
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        border-color: rgba(88,166,255,0.3);
    }
    .metric-card .count {
        font-size: 34px;
        font-weight: 800;
        line-height: 1;
    }
    .metric-card .label {
        font-size: 10px;
        text-transform: uppercase;
        color: #8b949e;
        margin-top: 6px;
        letter-spacing: 1px;
        font-weight: 600;
    }
    .critical { color: #ff4444; }
    .high     { color: #ff8c00; }
    .medium   { color: #f0c040; }
    .low      { color: #3fb950; }
    .verified { color: #39d353; }
    .candidate{ color: #f0c040; }
    .detected { color: #58a6ff; }
    .total    { color: #58a6ff; }

    /* ── Finding cards ── */
    .finding-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-left: 4px solid #30363d;
        border-radius: 12px;
        padding: 16px 18px;
        margin-bottom: 12px;
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    .finding-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.3); }
    .finding-card.critical { border-left-color: #ff4444; }
    .finding-card.high     { border-left-color: #ff8c00; }
    .finding-card.medium   { border-left-color: #f0c040; }
    .finding-card.low      { border-left-color: #3fb950; }
    .finding-card.dismissed { opacity: 0.45; }

    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        margin-right: 6px;
        letter-spacing: 0.3px;
    }
    .badge-critical { background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
    .badge-high     { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,140,0,0.3); }
    .badge-medium   { background: rgba(240,192,64,0.15); color: #f0c040; border: 1px solid rgba(240,192,64,0.3); }
    .badge-low      { background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
    .badge-verified { background: rgba(57,211,83,0.15); color: #39d353; border: 1px solid rgba(57,211,83,0.3); }
    .badge-candidate{ background: rgba(240,192,64,0.15); color: #f0c040; border: 1px solid rgba(240,192,64,0.3); }
    .badge-detected { background: rgba(88,166,255,0.15); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }

    /* ── Buttons ── */
    .stButton > button {
        background: linear-gradient(135deg, #1f6feb 0%, #58a6ff 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 10px 24px;
        font-weight: 700;
        letter-spacing: 0.3px;
        box-shadow: 0 4px 12px rgba(31,111,235,0.3);
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #388bfd 0%, #79c0ff 100%);
        box-shadow: 0 6px 20px rgba(31,111,235,0.4);
        transform: translateY(-1px);
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: #010409;
        border-right: 1px solid #21262d;
    }

    /* ── Log box ── */
    .log-box {
        background: #010409;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #8b949e;
        max-height: 320px;
        overflow-y: auto;
        white-space: pre-wrap;
        line-height: 1.5;
    }

    /* ── Filter bar ── */
    .filter-bar {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 16px;
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
    }

    /* hide default expander border */
    .streamlit-expanderHeader { font-weight: 600; }

    /* scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0d1117; }
    ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #58a6ff; }
</style>
""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
    <h1>🔍 WebVuln<span>Scanner</span> <span style="font-size:14px;color:#3fb950;background:rgba(57,211,83,0.12);padding:3px 10px;border-radius:20px;border:1px solid rgba(57,211,83,0.3);">v1.0</span></h1>
    <p>Hybrid Web Vulnerability Scanner — Static + Dynamic + AI Analysis &nbsp;•&nbsp; OWASP Top 10 &nbsp;•&nbsp; Interactive triage</p>
</div>
""", unsafe_allow_html=True)


# ── Constants ─────────────────────────────────────────────────────────────────
OPENROUTER_FREE_MODELS = [
    "openrouter/free",
    "cohere/north-mini-code:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "dots-studio/dots-3-note-preview:free",
]

# ── Sidebar — Scan Configuration ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Scan Configuration")

    # Target
    st.markdown("**🎯 Target**")
    target_url = st.text_input(
        "Target URL",
        value="http://localhost/dvwa",
        help="The URL of the application to scan",
        placeholder="http://localhost/dvwa"
    )
    source_dir = st.text_input(
        "Source Directory",
        value="",
        help="Path to source code for hybrid analysis (e.g. C:\\xampp\\htdocs\\dvwa)",
        placeholder="C:\\xampp\\htdocs\\dvwa"
    )
    st.divider()

    # Modules
    st.markdown("**🧩 Modules**")
    col1, col2 = st.columns(2)
    with col1:
        sqli      = st.checkbox("SQLi",        value=True, help="SQL Injection")
        xss       = st.checkbox("XSS",         value=True, help="Reflected XSS")
        cmdi      = st.checkbox("CMDi",        value=True, help="Command Injection")
    with col2:
        traversal = st.checkbox("Traversal",   value=True, help="Path Traversal")
        idor      = st.checkbox("IDOR",        value=True, help="Insecure Direct Object Reference")
        headers   = st.checkbox("Headers",     value=True, help="Security Headers")

    st.divider()

    # Authentication
    with st.expander("🔐 Authentication", expanded=False):
        username = st.text_input("Username", value="", placeholder="admin")
        password = st.text_input("Password", value="", type="password", placeholder="password")
        difficulty = st.selectbox("DVWA Level", ["(auto)", "low", "medium", "high", "impossible"], index=1, help="Sets DVWA security level via /security.php")

    # AI
    with st.expander("🤖 AI Enhancement", expanded=True):
        ai_provider = st.selectbox(
            "Provider",
            options=["openrouter", "groq", "gemini", "deepseek-flash", "deepseek-pro", "none"],
            index=0,
            help="OpenRouter = free, 35+ models (no card). Groq/Gemini also free."
        )
        openrouter_model = None
        if ai_provider == "openrouter":
            openrouter_model = st.selectbox("OpenRouter Model (free)", OPENROUTER_FREE_MODELS, index=0, help="Swap without code change. All listed are :free")
        no_ai = st.checkbox("Disable AI (faster, no API calls)", value=False)
        st.caption(f"Free tier: OpenRouter 50/day, Groq 14k/day. This scan: ~10-46 calls.")

    # Advanced
    with st.expander("🔧 Advanced", expanded=False):
        colA, colB = st.columns(2)
        with colA:
            timeout = st.number_input("Timeout (s)", min_value=5, max_value=60, value=10, help="Per-request timeout")
            max_pages = st.number_input("Max pages", min_value=10, max_value=500, value=50, help="Crawler page cap")
            max_response = st.number_input("Max response (KB)", min_value=256, max_value=10240, value=2048, help="Cap response body to prevent OOM (2 MiB default)")
        with colB:
            ai_max_findings = st.number_input("AI Max Findings", min_value=0, max_value=100, value=0, help="0 = all, else cap by severity")
            ai_max_remed = st.number_input("AI Max Remediations", min_value=0, max_value=100, value=0, help="0 = all, else cap AI remediation")
            allow_subdomains = st.checkbox("Allow subdomains", value=False, help="If OFF, scope is exact host only (sibling-subdomain fix)")
        c1, c2 = st.columns(2)
        with c1:
            verbose = st.checkbox("Verbose", value=False)
        with c2:
            quiet = st.checkbox("Quiet", value=False, help="Suppress crawler noise")
        output_format = st.selectbox("Output format", ["both", "html", "json"], index=0)

    st.divider()

    # History — load past reports without re-scanning
    st.markdown("**📚 History**")
    reports_dir = Path("reports")
    report_files = sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if reports_dir.exists() else []
    history_choice = st.selectbox(
        "Load past report",
        options=["(new scan)"] + [p.name for p in report_files[:20]],
        index=0,
        help="Pick a previous JSON report to view without re-scanning"
    )
    if history_choice != "(new scan)":
        st.info(f"Will load `{history_choice}` instead of scanning.")

    scan_button = st.button("🚀 Start Scan", use_container_width=True, type="primary")
    st.caption("CLI parity: all flags synced with `main.py`")

# ── Helpers ───────────────────────────────────────────────────────────────────
def base_command():
    # Always use the current Python + main.py directly — most reliable on
    # Windows where `wvs` may be a .bat/.exe that needs shell=True and
    # paths contain spaces and `&` (e.g. "10 - Security & Projects").
    # Using sys.executable + absolute main.py avoids WinError 2.
    root = os.path.dirname(os.path.abspath(__file__))
    return [sys.executable, os.path.join(root, "main.py")]

def build_command():
    cmd = base_command()
    if target_url:
        cmd.extend(["--url", target_url])
    if source_dir:
        cmd.extend(["--src", source_dir])
    active = []
    if sqli:      active.append("sqli")
    if xss:       active.append("xss")
    if cmdi:      active.append("cmdi")
    if traversal: active.append("traversal")
    if idor:      active.append("idor")
    if headers:   active.append("headers")
    if active and len(active) < 6:
        cmd.extend(["--scan", ",".join(active)])
    if username:
        cmd.extend(["--username", username])
    if password:
        cmd.extend(["--password", password])
    if difficulty != "(auto)":
        cmd.extend(["--difficulty", difficulty])
    if no_ai:
        cmd.append("--no-ai")
    elif ai_provider != "openrouter" or openrouter_model != OPENROUTER_FREE_MODELS[0]:
        # openrouter is default, but if user picked a non-default model we need to pass it via config override
        # For now we pass --ai-provider; model is via config.OPENROUTER_MODEL env
        cmd.extend(["--ai-provider", ai_provider])
    else:
        cmd.extend(["--ai-provider", ai_provider])
    cmd.extend(["--timeout", str(timeout)])
    cmd.extend(["--max-pages", str(max_pages)])
    cmd.extend(["--output-format", output_format])
    cmd.extend(["--max-response-kb", str(max_response)])
    cmd.extend(["--ai-max-findings", str(int(ai_max_findings))])
    cmd.extend(["--ai-max-remediations", str(int(ai_max_remed))])
    if allow_subdomains:
        cmd.append("--allow-subdomains")
    # These are config-only today — we inject via env so the scan picks them up
    # (main.py reads config, but we can also override via env prefix if needed; for now we just ensure config.py has defaults)
    report_name = f"ui_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    cmd.extend(["--report-name", report_name])
    if verbose:
        cmd.append("--verbose")
    if quiet:
        cmd.append("--quiet")
    return cmd, report_name

def sev_order(s): return {"critical":0,"high":1,"medium":2,"low":3}.get(s.lower(), 9)

def _render_metrics(scan_info, summary):
    cols = st.columns(8)
    metrics = [
        ("Total",     scan_info.get("total", 0),        "total"),
        ("Critical",  summary.get("critical", 0),       "critical"),
        ("High",      summary.get("high", 0),           "high"),
        ("Medium",    summary.get("medium", 0),         "medium"),
        ("Low",       summary.get("low", 0),            "low"),
        ("Verified",  summary.get("type1", 0),          "verified"),
        ("Candidate", summary.get("type2", 0),          "candidate"),
        ("Detected",  summary.get("type3", 0),          "detected"),
    ]
    for col, (label, count, css_class) in zip(cols, metrics):
        with col:
            st.markdown(f"""
            <div class="metric-card {css_class}">
                <div class="count">{count}</div>
                <div class="label">{label}</div>
            </div>
            """, unsafe_allow_html=True)


def _evidence_language(finding: dict) -> str:
    """Pick a Streamlit code-block language from the finding evidence."""
    file = (finding.get("file") or "").lower()
    url  = (finding.get("url") or "").lower()
    evidence = (finding.get("evidence_static") or "")[:500].lower()
    if ".php" in file or ".php" in url or "<?php" in evidence:
        return "php"
    if ".py" in file or ".py" in url or "def " in evidence:
        return "python"
    if ".js" in file or ".ts" in file or ".js" in url or ".ts" in url:
        return "javascript"
    if ".java" in file or ".java" in url:
        return "java"
    if ".go" in file or ".go" in url:
        return "go"
    if ".rb" in file or ".rb" in url:
        return "ruby"
    if ".cs" in file or ".cs" in url:
        return "csharp"
    return "text"


def display_findings(findings, key_prefix=""):
    """Streamlit-native findings with filter/sort/triage."""
    if not findings:
        st.info("✨ No vulnerabilities found!")
        return

    # ── Filter bar ────────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns([2.2, 1.6, 1.6, 1.2])
    with c1:
        query = st.text_input("🔍 Search", placeholder="URL, param, type, OWASP...", key=f"{key_prefix}_q", label_visibility="collapsed")
    with c2:
        sev_filter = st.multiselect("Severity", ["Critical","High","Medium","Low"], default=[], key=f"{key_prefix}_sev", placeholder="Severity")
    with c3:
        type_opts = sorted(set(f.get("type","") for f in findings))
        type_filter = st.multiselect("Type", type_opts, default=[], key=f"{key_prefix}_type", placeholder="Type")
    with c4:
        sort_by = st.selectbox("Sort", ["Severity","Type","URL","Confidence"], index=0, key=f"{key_prefix}_sort", label_visibility="collapsed")

    status_filter = st.multiselect("Status", ["Verified","Candidate","Detected"], default=[], key=f"{key_prefix}_status", placeholder="Status", label_visibility="collapsed")

    # Apply filters
    filtered = []
    q = (query or "").lower()
    sev_set = set(s.lower() for s in sev_filter)
    type_set = set(type_filter)
    status_map = {1:"Verified",2:"Candidate",3:"Detected"}
    status_set = set(status_filter)
    for f in findings:
        if sev_set and f.get("severity","").lower() not in sev_set:
            continue
        if type_set and f.get("type","") not in type_set:
            continue
        if status_set and status_map.get(f.get("finding_type",3), "") not in status_set:
            continue
        if q:
            hay = f"{f.get('url','')} {f.get('parameter','')} {f.get('type','')} {f.get('owasp','')}".lower()
            if q not in hay:
                continue
        filtered.append(f)

    # Sort
    if sort_by == "Severity":
        filtered.sort(key=lambda x: sev_order(x.get("severity","")))
    elif sort_by == "Type":
        filtered.sort(key=lambda x: x.get("type",""))
    elif sort_by == "URL":
        filtered.sort(key=lambda x: x.get("url",""))
    elif sort_by == "Confidence":
        filtered.sort(key=lambda x: x.get("confidence",0), reverse=True)

    st.caption(f"Showing **{len(filtered)} / {len(findings)}** findings" + (f" • filtered by `{query}`" if q else ""))

    if not filtered:
        st.warning("No findings match the current filters.")
        return

    # ── Cards ─────────────────────────────────────────────────────────────────
    for idx, f in enumerate(filtered):
        sev = f.get("severity", "Medium")
        sev_l = sev.lower()
        ftype = f.get("finding_type", 3)
        type_label = "✅ Verified" if ftype==1 else ("⚠️ Candidate" if ftype==2 else "🔍 Detected")
        dismissed = f.get("status") == "dismissed"
        card_cls = f"finding-card {sev_l}" + (" dismissed" if dismissed else "")

        # Use expander for each finding — keeps page fast with 40+ findings
        title = f"[{f.get('type','').upper()}] {f.get('url') or f.get('file','Unknown')} — `{f.get('parameter','')}`" if f.get('parameter') else f"[{f.get('type','').upper()}] {f.get('url') or f.get('file','Unknown')}"
        with st.expander(f"{sev} • {title} • {type_label}", expanded=(idx==0)):
            cols = st.columns([1,1,1])
            cols[0].markdown(f"**Severity:** :{'red' if sev_l=='critical' else 'orange' if sev_l=='high' else 'gray'}[{sev}]")
            cols[1].markdown(f"**Type:** {type_label}")
            cols[2].markdown(f"**Confidence:** {int(f.get('confidence',0)*100)}%")
            if f.get("owasp"):
                st.caption(f.get("owasp"))

            # Triage
            tcol1, tcol2 = st.columns([1,1])
            with tcol1:
                dismiss = st.checkbox("Mark as false positive (dismiss)", value=dismissed, key=f"{key_prefix}_dismiss_{idx}")
                if dismiss != dismissed:
                    st.toast("Triage state is local — export filtered JSON to persist.", icon="💡")
            with tcol2:
                note = st.text_input("Note", value=f.get("triage_note",""), key=f"{key_prefix}_note_{idx}", placeholder="Add a note...")
                if note:
                    f["triage_note"] = note

            if f.get("evidence_static"):
                st.markdown("**Static Evidence**")
                st.code(f.get("evidence_static"), language=_evidence_language(f))
            if f.get("evidence_dynamic"):
                st.markdown("**Dynamic Evidence**")
                st.code(f.get("evidence_dynamic"), language="text")
                if f.get("payload"):
                    st.markdown(f"**Payload:** `{f.get('payload')}`")
            if f.get("ai_error"):
                st.warning(f"**AI Status:** {f.get('ai_error')}")
            if f.get("ai_note"):
                st.info(f"**AI Review:** {f.get('ai_note')}")
            if f.get("remediation"):
                st.success(f"**Remediation:** {f.get('remediation')}")

            if dismissed:
                st.error("Dismissed as false positive — excluded from totals when exported.")

    # Export filtered
    if st.button("📥 Export filtered JSON", key=f"{key_prefix}_export"):
        export = [f for f in filtered if not f.get("status")=="dismissed" or f.get("triage_note")]
        st.download_button("Download filtered findings", data=json.dumps(export, indent=2), file_name=f"filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", mime="application/json", key=f"{key_prefix}_dl")

# ── Main Logic ────────────────────────────────────────────────────────────────
if scan_button and history_choice == "(new scan)":
    if not target_url and not source_dir:
        st.error("⚠️ Please provide a target URL or source directory.")
    else:
        cmd, report_name = build_command()
        # Mask password in displayed command
        display_cmd = list(cmd)
        if "--password" in display_cmd:
            idx = display_cmd.index("--password")
            if idx+1 < len(display_cmd):
                display_cmd[idx+1] = "********"
        st.code(" ".join(display_cmd), language="bash")

        # Live streaming
        st.markdown("### 🔄 Live Scan Log")
        log_placeholder = st.empty()
        progress_bar = st.progress(0)
        phase_labels = ["Static Analysis","Crawling Target","Injection Testing","Correlation","AI Enhancement","Generating Report"]
        current_phase = 0

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        # Pass OpenRouter model via env so main.py/config can pick it up without editing config.py
        if ai_provider == "openrouter" and openrouter_model:
            env["OPENROUTER_MODEL"] = openrouter_model

        logs = []
        try:
            # Run from project root so reports/ and config.py resolve correctly,
            # and use list-form to handle spaces and `&` in paths like
            # "10 - Security & Projects" without shell quoting issues.
            root = os.path.dirname(os.path.abspath(__file__))
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                cwd=root,
                bufsize=1
            )
            # Stream line by line
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                logs.append(line)
                # Update phase progress heuristically
                low = line.lower()
                if "static analysis" in low: current_phase = 0
                elif "crawling target" in low: current_phase = 1
                elif "sql injection" in low or "cross-site" in low or "command injection" in low: current_phase = 2
                elif "correlation engine" in low: current_phase = 3
                elif "ai enhancement" in low: current_phase = 4
                elif "generating report" in low: current_phase = 5
                progress_bar.progress(min(100, int((current_phase+1)/6*100)))
                # Keep last 80 lines visible
                log_placeholder.markdown(f'<div class="log-box">{"".join(logs[-80:])}</div>', unsafe_allow_html=True)

            proc.wait(timeout=600)
            progress_bar.progress(100)

            stdout = "".join(logs)
            if proc.returncode != 0 and "complete" not in stdout.lower():
                st.error(f"Scan failed (exit {proc.returncode})")
                st.code(stdout[-6000:], language="text")
            else:
                st.success("✅ Scan completed!")

                json_path = Path("reports") / f"{report_name}.json"
                html_path = Path("reports") / f"{report_name}.html"

                if json_path.exists():
                    with open(json_path, 'r', encoding='utf-8') as fp:
                        data = json.load(fp)
                    scan_info = data.get("scan_info", {})
                    summary = scan_info.get("summary", {})
                    findings = data.get("findings", [])

                    # ── Summary Metrics ────────────────────────────────
                    st.markdown("### 📊 Scan Summary")
                    _render_metrics(scan_info, summary)

                    # ── Charts ──────────────────────────────────────────
                    if findings:
                        c1, c2 = st.columns(2)
                        with c1:
                            st.markdown("**Findings by Severity**")
                            sev_data = {k: summary.get(k.lower(),0) for k in ["Critical","High","Medium","Low"]}
                            st.bar_chart(sev_data, color="#58a6ff")
                        with c2:
                            st.markdown("**Findings by Type**")
                            from collections import Counter
                            type_counts = Counter(f.get("type","unknown") for f in findings)
                            st.bar_chart(type_counts, color="#bc8cff")

                    # ── Findings ────────────────────────────────────────
                    if findings:
                        st.markdown(f"### 🐛 Findings ({len(findings)})")
                        display_findings(findings, key_prefix=report_name)
                    else:
                        st.info("✨ No vulnerabilities found!")

                    # ── Downloads & Preview ─────────────────────────────
                    st.markdown("### 📥 Reports")
                    col1, col2 = st.columns(2)
                    if html_path.exists():
                        with open(html_path, 'rb') as fp:
                            col1.download_button("📄 HTML", data=fp.read(), file_name=html_path.name, mime="text/html", use_container_width=True)
                    if json_path.exists():
                        with open(json_path, 'rb') as fp:
                            col2.download_button("📋 JSON", data=fp.read(), file_name=json_path.name, mime="application/json", use_container_width=True)

                    if html_path.exists():
                        with st.expander("👁️ Preview HTML Report", expanded=False):
                            st.components.v1.html(open(html_path, 'r', encoding='utf-8').read(), height=600, scrolling=True)

                    with st.expander("🖥️ Full CLI Output"):
                        st.code(stdout[-12000:] or "(no output)", language="text")
                else:
                    st.warning("Scan completed but no report was generated.")
                    st.code("".join(logs[-120:]), language="text")

        except subprocess.TimeoutExpired:
            st.error("⏱️ Scan timed out after 10 minutes.")
        except FileNotFoundError as e:
            st.error(f"❌ Could not start scanner: {e}\n\nCommand was: `{' '.join(cmd)}`\n\nTry running `setup.bat` again to reinstall the `wvs` command.")
        except Exception as e:
            st.error(f"❌ Error: {e}")

elif history_choice != "(new scan)":
    # ── History mode — load past report ─────────────────────────────────────
    st.markdown(f"### 📚 Loaded: `{history_choice}`")
    jpath = Path("reports") / history_choice
    hpath = jpath.with_suffix(".html")
    try:
        with open(jpath, 'r', encoding='utf-8') as fp:
            data = json.load(fp)
        scan_info = data.get("scan_info", {})
        summary = scan_info.get("summary", {})
        findings = data.get("findings", [])
        st.caption(f"Target: {scan_info.get('target_url','-')} • {scan_info.get('date','-')} • {scan_info.get('ai_provider','-')} • {scan_info.get('total',0)} findings")

        _render_metrics(scan_info, summary)

        if findings:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Findings by Severity**")
                sev_data = {k: summary.get(k.lower(),0) for k in ["Critical","High","Medium","Low"]}
                st.bar_chart(sev_data)
            with c2:
                from collections import Counter
                st.markdown("**Findings by Type**")
                st.bar_chart(Counter(f.get("type","unknown") for f in findings))

        if findings:
            st.markdown(f"### 🐛 Findings ({len(findings)})")
            display_findings(findings, key_prefix="history")

        col1, col2 = st.columns(2)
        if hpath.exists():
            with open(hpath, 'rb') as fp:
                col1.download_button("📄 Download HTML", data=fp.read(), file_name=hpath.name, mime="text/html", key="hist_html")
        with open(jpath, 'rb') as fp:
            col2.download_button("📋 Download JSON", data=fp.read(), file_name=jpath.name, mime="application/json", key="hist_json")

        if hpath.exists():
            with st.expander("👁️ Preview HTML"):
                st.components.v1.html(open(hpath, 'r', encoding='utf-8').read(), height=600, scrolling=True)

    except Exception as e:
        st.error(f"Could not load {history_choice}: {e}")

else:
    # ── Welcome Screen ───────────────────────────────────────────────────────
    st.markdown("""
    ### 👋 Welcome to WebVulnScanner
    Hybrid web vulnerability scanner — static code analysis, dynamic injection testing, and AI-powered triage.
    """)
    c1, c2, c3 = st.columns(3)
    feats = [
        ("🎯 Hybrid", "Static source analysis + dynamic injection testing in one report."),
        ("🤖 AI Triage", "Optional AI review for false positives and language-aware remediation advice."),
        ("🎨 Interactive", "Filter, search, sort, dismiss, and export findings from the browser."),
    ]
    for col, (title, desc) in zip([c1,c2,c3], feats):
        with col:
            st.markdown(f"""
            <div style="background: linear-gradient(145deg, #161b22, #1c2128); border: 1px solid #30363d; border-radius: 12px; padding: 18px; margin-bottom: 12px;">
                <div style="color: #58a6ff; font-weight: 800; font-size: 14px;">{title}</div>
                <div style="color: #e6edf3; font-size: 13px; margin-top: 6px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    cols = st.columns(3)
    modules_info = [
        ("💉 SQL Injection",     "Error/Time/Boolean-based"),
        ("⚡ XSS",                "Reflected, unencoded check"),
        ("🖥️ Command Injection",  "Output + time-based, baseline"),
        ("📁 Path Traversal",    "Tier-1 file leak + Tier-2 baseline"),
        ("🔓 IDOR",               "Same-ID noise gate, sequential IDs"),
        ("🛡️ Security Headers",  "Missing CSP, framing, etc."),
    ]
    for i, (name, desc) in enumerate(modules_info):
        with cols[i % 3]:
            st.markdown(f"""
            <div style="background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 14px; margin-bottom: 10px;">
                <div style="color: #58a6ff; font-weight: 700; font-size: 13px;">{name}</div>
                <div style="color: #8b949e; font-size: 11px; margin-top: 4px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.info("👈 Configure your scan in the sidebar and hit **🚀 Start Scan** — or pick a past report from **📚 History**.")


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #8b949e; font-size: 11px;'>"
    "WebVulnScanner v1.0 — Hybrid Web Vulnerability Scanner &nbsp;•&nbsp; "
    "<a href='https://github.com/moadh704/webvulnscanner' style='color:#58a6ff;'>GitHub</a>"
    "</div>",
    unsafe_allow_html=True
)
