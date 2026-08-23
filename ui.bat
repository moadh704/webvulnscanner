@echo off
chcp 65001 >nul 2>&1
setlocal

REM ── WebVulnScanner - Web UI Launcher ───────────────────────────────────────
REM Double-click this file to start the Streamlit dashboard.
REM Handles venv creation, dependency checks, and port conflicts automatically.

cd /d "%~dp0"

echo ========================================
echo   WebVulnScanner - Web UI
echo ========================================
echo.

REM 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.8+ from https://www.python.org/downloads/
    echo         Make sure "Add Python to PATH" is checked during install.
    pause
    exit /b 1
)

REM 2. Ensure venv exists
if not exist "venv\Scripts\activate.bat" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv.
        pause
        exit /b 1
    )
)

call venv\Scripts\activate.bat >nul 2>&1

REM 3. Ensure Streamlit is installed
python -c "import streamlit" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing dependencies (first run, may take a minute)...
    python -m pip install --upgrade pip --quiet --disable-pip-version-check
    pip install -r requirements.txt --quiet --disable-pip-version-check
)

REM 4. Find free port (8501 -> 8502 if busy)
set PORT=8501
netstat -ano | findstr ":8501" >nul 2>&1
if not errorlevel 1 (
    echo [INFO] Port 8501 busy, trying 8502...
    set PORT=8502
)

echo.
echo Starting Streamlit server...
echo   URL: http://localhost:%PORT%
echo   Press Ctrl+C to stop.
echo.

REM 5. Ensure config.py exists (holds API keys, gitignored)
if not exist "config.py" (
    if exist "config.example.py" (
        copy /y config.example.py config.py >nul
        echo [INFO] Created config.py from config.example.py - add your API keys there.
    )
)

set PYTHONIOENCODING=utf-8
python -m streamlit run app.py --server.port %PORT% --server.headless false

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start Streamlit. Try:
    echo   1. Run setup.bat again
    echo   2. Check app.py for syntax errors: python -m py_compile app.py
    pause
)
