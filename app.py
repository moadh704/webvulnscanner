"""
WebVulnScanner — Streamlit Web UI
Run with: streamlit run app.py
"""

import streamlit as st
import subprocess
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebVulnScanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS — Dark Theme Matching the HTML Report ─────────────────────────
st.markdown("""
<style>
    .stApp {
        background: #0d1117;
    }
    .main-header {
        background: linear-gradient(135deg, #0d1117, #1a2332);
        padding: 30px;
        border-radius: 12px;
        border: 1px solid #30363d;
        margin-bottom: 24px;
    }
    .main-header h1 {
        color: #58a6ff;
        margin: 0;
        font-size: 28px;
    }
    .main-header p {
        color: #8b949e;
        margin: 4px 0 0 0;
    }
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .metric-card .count {
        font-size: 32px;
        font-weight: 700;
    }
    .metric-card .label {
        font-size: 11px;
        text-transform: uppercase;
        color: #8b949e;
        margin-top: 4px;
        letter-spacing: 0.5px;
    }
    .critical { color: #ff4444; border-color: #ff4444 !important; }
    .high     { color: #ff8c00; border-color: #ff8c00 !important; }
    .medium   { color: #f0c040; border-color: #f0c040 !important; }
    .low      { color: #3fb950; border-color: #3fb950 !important; }
    .verified { color: #39d353; border-color: #39d353 !important; }
    .candidate{ color: #f0c040; border-color: #f0c040 !important; }
    .detected { color: #58a6ff; border-color: #58a6ff !important; }

    .finding-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-left: 4px solid #30363d;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 10px;
    }
    .finding-card.critical { border-left-color: #ff4444; }
    .finding-card.high     { border-left-color: #ff8c00; }
    .finding-card.medium   { border-left-color: #f0c040; }
    .finding-card.low      { border-left-color: #3fb950; }

    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 700;
        margin-right: 6px;
    }
    .badge-critical { background: rgba(255,68,68,0.2); color: #ff4444; border: 1px solid rgba(255,68,68,0.4); }
    .badge-high     { background: rgba(255,140,0,0.2); color: #ff8c00; border: 1px solid rgba(255,140,0,0.4); }
    .badge-medium   { background: rgba(240,192,64,0.2); color: #f0c040; border: 1px solid rgba(240,192,64,0.4); }
    .badge-low      { background: rgba(63,185,80,0.2); color: #3fb950; border: 1px solid rgba(63,185,80,0.4); }
    .badge-verified { background: rgba(57,211,83,0.15); color: #39d353; border: 1px solid rgba(57,211,83,0.3); }
    .badge-candidate{ background: rgba(240,192,64,0.15); color: #f0c040; border: 1px solid rgba(240,192,64,0.3); }
    .badge-detected { background: rgba(88,166,255,0.15); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }

    .stButton > button {
        background: #1f6feb;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 8px 24px;
        font-weight: 600;
    }
    .stButton > button:hover {
        background: #388bfd;
    }
</style>
""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🔍 WebVulnScanner</h1>
    <p>Hybrid Web Vulnerability Scanner — Static + Dynamic + AI Analysis</p>
</div>
""", unsafe_allow_html=True)


# ── Sidebar — Scan Configuration ──────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Scan Configuration")

    # Target
    st.subheader("Target")
    target_url = st.text_input(
        "Target URL",
        value="http://localhost/dvwa",
        help="The URL of the application to scan"
    )

    source_dir = st.text_input(
        "Source Directory (optional)",
        value="",
        help="Path to source code for hybrid (static + dynamic) analysis"
    )

    st.markdown("---")

    # Modules
    st.subheader("Modules")
    col1, col2 = st.columns(2)
    with col1:
        sqli      = st.checkbox("SQL Injection",   value=True)
        xss       = st.checkbox("XSS",              value=True)
        cmdi      = st.checkbox("Command Inj.",     value=True)
    with col2:
        traversal = st.checkbox("Path Traversal",   value=True)
        idor      = st.checkbox("IDOR",              value=True)
        headers   = st.checkbox("Security Headers", value=True)

    st.markdown("---")

    # Authentication
    with st.expander("🔐 Authentication (optional)"):
        username = st.text_input("Username", value="")
        password = st.text_input("Password", value="", type="password")

    # Advanced
    with st.expander("🔧 Advanced Options"):
        ai_provider = st.selectbox(
            "AI Provider",
            options=["groq", "gemini", "none"],
            index=0
        )
        no_ai = st.checkbox("Disable AI layer (faster)", value=False)
        timeout = st.number_input("Request timeout (s)", min_value=5, max_value=60, value=10)
        max_pages = st.number_input("Max crawl pages", min_value=10, max_value=500, value=50)
        output_format = st.selectbox("Output format", ["both", "html", "json"], index=0)

    st.markdown("---")
    scan_button = st.button("🚀 Start Scan", use_container_width=True, type="primary")


# ── Build CLI Command ─────────────────────────────────────────────────────────
def build_command():
    """Build the WebVulnScanner CLI command from UI inputs."""
    cmd = ["WebVulnScanner"]

    if target_url:
        cmd.extend(["--url", target_url])
    if source_dir:
        cmd.extend(["--src", source_dir])

    # Build active modules
    active = []
    if sqli:      active.append("sqli")
    if xss:       active.append("xss")
    if cmdi:      active.append("cmdi")
    if traversal: active.append("traversal")
    if idor:      active.append("idor")
    if headers:   active.append("headers")
    if active:
        cmd.extend(["--scan", ",".join(active)])

    if username:
        cmd.extend(["--username", username])
    if password:
        cmd.extend(["--password", password])

    if no_ai:
        cmd.append("--no-ai")
    elif ai_provider != "groq":
        cmd.extend(["--ai-provider", ai_provider])

    cmd.extend(["--timeout", str(timeout)])
    cmd.extend(["--max-pages", str(max_pages)])
    cmd.extend(["--output-format", output_format])

    # Custom report name with timestamp
    report_name = f"ui_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    cmd.extend(["--report-name", report_name])

    return cmd, report_name


# ── Findings Display ──────────────────────────────────────────────────────────
def display_findings(findings):
    """Render findings as cards."""
    for f in findings:
        sev = f.get("severity", "Medium").lower()
        ftype = f.get("finding_type", 3)

        if ftype == 1:
            type_badge = '<span class="badge badge-verified">✓ Verified</span>'
        elif ftype == 2:
            type_badge = '<span class="badge badge-candidate">⚠ Candidate</span>'
        else:
            type_badge = '<span class="badge badge-detected">◎ Detected</span>'

        sev_badge = f'<span class="badge badge-{sev}">{f.get("severity", "Medium")}</span>'

        url = f.get("url", "Unknown")
        param = f.get("parameter", "")
        vuln_type = f.get("type", "unknown").upper()
        owasp = f.get("owasp", "")

        title = f"<b>[{vuln_type}]</b> {url}"
        if param:
            title += f' — <code style="color:#79c0ff">{param}</code>'

        card_html = f"""
        <div class="finding-card {sev}">
            <div style="margin-bottom: 10px;">
                {sev_badge}{type_badge}
                <span style="color: #8b949e; font-size: 11px;">{owasp}</span>
            </div>
            <div style="color: #e6edf3; font-size: 14px; margin-bottom: 8px;">{title}</div>
        """

        if f.get("evidence_dynamic"):
            card_html += f"""
            <div style="background: #21262d; border-radius: 6px; padding: 10px; margin-top: 8px; font-family: Courier; font-size: 12px; color: #79c0ff;">
                <b style="color: #8b949e;">Evidence:</b> {f.get("evidence_dynamic")}
            </div>
            """

        if f.get("payload"):
            card_html += f"""
            <div style="font-size: 11px; color: #8b949e; margin-top: 6px;">
                <b>Payload:</b> <code style="color:#79c0ff">{f.get("payload")}</code>
            </div>
            """

        if f.get("remediation"):
            card_html += f"""
            <div style="background: rgba(63,185,80,0.05); border: 1px solid rgba(63,185,80,0.2); border-radius: 6px; padding: 10px; margin-top: 10px; font-size: 12px; color: #e6edf3;">
                <b style="color: #3fb950;">💡 Remediation:</b> {f.get("remediation")}
            </div>
            """

        card_html += "</div>"
        st.markdown(card_html, unsafe_allow_html=True)


# ── Main Logic ────────────────────────────────────────────────────────────────
if scan_button:
    if not target_url and not source_dir:
        st.error("⚠️ Please provide a target URL or source directory.")
    else:
        cmd, report_name = build_command()

        # Show command being run
        st.code(" ".join(cmd), language="bash")

        # Run the scan
        with st.spinner("🔍 Scanning... this may take a few minutes"):
            try:
                # Set encoding to UTF-8 for Windows to handle Unicode characters
                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    shell=(os.name == 'nt'),
                    encoding='utf-8',
                    errors='replace',
                    env=env
                )

                if result.returncode != 0 and "complete" not in (result.stdout or "").lower():
                    st.error(f"Scan failed:\n```\n{result.stderr}\n```")
                else:
                    st.success("✅ Scan completed!")

                    # Try to load the JSON report
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
                        cols = st.columns(8)
                        metrics = [
                            ("Total",     scan_info.get("total", 0),        ""),
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

                        # ── Findings ────────────────────────────────────────
                        if findings:
                            st.markdown(f"### 🐛 Findings ({len(findings)})")
                            display_findings(findings)
                        else:
                            st.info("✨ No vulnerabilities found!")

                        # ── Download Buttons ────────────────────────────────
                        st.markdown("### 📥 Download Reports")
                        col1, col2 = st.columns(2)

                        if html_path.exists():
                            with open(html_path, 'rb') as fp:
                                col1.download_button(
                                    label="📄 Download HTML Report",
                                    data=fp.read(),
                                    file_name=html_path.name,
                                    mime="text/html",
                                    use_container_width=True
                                )

                        if json_path.exists():
                            with open(json_path, 'rb') as fp:
                                col2.download_button(
                                    label="📋 Download JSON Report",
                                    data=fp.read(),
                                    file_name=json_path.name,
                                    mime="application/json",
                                    use_container_width=True
                                )

                        # ── Show CLI output (collapsible) ──────────────────
                        with st.expander("🖥️ Show CLI Output"):
                            st.code(result.stdout or "(no output)", language="text")
                    else:
                        st.warning("Scan completed but no report was generated.")
                        with st.expander("🖥️ Show CLI Output"):
                            st.code(result.stdout or "(no output)", language="text")

            except subprocess.TimeoutExpired:
                st.error("⏱️ Scan timed out after 10 minutes.")
            except Exception as e:
                st.error(f"❌ Error: {e}")

else:
    # ── Welcome Screen ───────────────────────────────────────────────────────
    st.markdown("""
    ### Welcome to WebVulnScanner

    A hybrid web vulnerability scanner combining static code analysis,
    dynamic injection testing, and AI-powered false positive filtering.

    **Quick Start:**
    1. Enter a target URL in the sidebar
    2. Select the modules to run
    3. Click **🚀 Start Scan**

    **Detection Modules:**
    """)

    cols = st.columns(3)
    modules_info = [
        ("💉 SQL Injection",     "Error/Time/Boolean-based detection"),
        ("⚡ XSS",                "Reflected payload detection"),
        ("🖥️ Command Injection",  "Output and time-based detection"),
        ("📁 Path Traversal",    "File inclusion and directory traversal"),
        ("🔓 IDOR",               "Sequential ID enumeration"),
        ("🛡️ Security Headers",  "Missing HTTP security headers"),
    ]

    for i, (name, desc) in enumerate(modules_info):
        with cols[i % 3]:
            st.markdown(f"""
            <div style="background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px; margin-bottom: 10px;">
                <div style="color: #58a6ff; font-weight: 700;">{name}</div>
                <div style="color: #8b949e; font-size: 12px; margin-top: 4px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #8b949e; font-size: 11px;'>"
    "WebVulnScanner v1.0 — Hybrid Web Vulnerability Scanner"
    "</div>",
    unsafe_allow_html=True
)