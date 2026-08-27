"""Simulate a real scan through the Streamlit UI using AppTest."""
import os
import sys
from streamlit.testing.v1 import AppTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app.py")

at = AppTest.from_file(APP, default_timeout=600)
at.run()

# Sidebar widgets
at.sidebar.text_input[0].set_value("http://localhost/dvwa")
at.sidebar.text_input[1].set_value(r"C:\xampp\htdocs\dvwa")
at.sidebar.text_input[2].set_value("admin")
at.sidebar.text_input[3].set_value("password")

# Advanced caps: stay inside free quota
at.sidebar.number_input[3].set_value(10)  # ai_max_findings
at.sidebar.number_input[4].set_value(10)  # ai_max_remed

# Start scan
at.sidebar.button[0].click()
at.run()

errors = [str(e.value) for e in at.error]
successes = [str(s.value) for s in at.success]
warnings = [str(w.value) for w in at.warning]
print("UI errors:", errors[:5])
print("UI success:", [s[:120] for s in successes][:5])
print("UI warnings:", [w[:120] for w in warnings][:5])

# A successful scan shows 'Scan completed!' and a new report file exists
ok = any("Scan completed" in s for s in successes)
print("UI_SCAN_OK:", ok)

if not ok:
    # dump last part of any visible code/log output for debugging
    for c in at.code[-3:]:
        print("code tail:", c.value[-500:])
