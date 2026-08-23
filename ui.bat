@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
echo ========================================
echo   WebVulnScanner - Web UI
echo ========================================
echo.
echo Starting Streamlit server at http://localhost:8501
echo Press Ctrl+C to stop.
echo.
REM Use venv if available, else system python
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -m streamlit run app.py --server.port 8501
) else (
    python -m streamlit run app.py --server.port 8501
)
pause
