@echo off
chcp 65001 >nul 2>&1
setlocal
echo ========================================
echo   WebVulnScanner — Installation
echo ========================================
echo.

REM 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.8+ from https://www.python.org/downloads/
    echo         Check "Add Python to PATH" during install.
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] Python %PYVER% found.

REM 2. Create venv
echo.
echo [1/4] Creating virtual environment...
if not exist "venv\Scripts\activate.bat" (
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Try running as Administrator.
        pause
        exit /b 1
    )
    echo       Created venv\
) else (
    echo       venv\ already exists — skipping.
)

call venv\Scripts\activate.bat >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Could not activate venv. Delete venv\ and try again.
    pause
    exit /b 1
)

REM 3. Upgrade pip + install deps
echo.
echo [2/4] Installing dependencies...
python -m pip install --upgrade pip --quiet --disable-pip-version-check
pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
    echo [WARN] pip install had errors — check your internet connection.
    echo        Try manually: pip install -r requirements.txt
)

REM 4. Install wvs command
echo.
echo [3/4] Installing wvs command...
pip install -e . --quiet --disable-pip-version-check
if errorlevel 1 (
    echo [WARN] Could not install wvs entry point — you can still use wvs.bat or python main.py
)

REM 5. Create config.py if missing
echo.
echo [4/4] Checking config...
if not exist "config.py" (
    if exist "config.example.py" (
        copy /y config.example.py config.py >nul
        echo       Created config.py from config.example.py
        echo       Edit config.py to add API keys (OpenRouter/Groq/Gemini).
    )
) else (
    echo       config.py already exists — skipping.
)

REM 6. Verify
echo.
echo Verifying...
python -m py_compile main.py app.py >nul 2>&1
if errorlevel 1 (
    echo [WARN] Syntax check failed — run: python -m py_compile main.py
) else (
    echo [OK]  main.py and app.py compile clean.
)
python -c "import requests, bs4, jinja2" >nul 2>&1
if errorlevel 1 (
    echo [WARN] Some deps missing — run: pip install -r requirements.txt
) else (
    echo [OK]  Core dependencies OK.
)

echo.
echo ========================================
echo   Installation complete!
echo ========================================
echo.
echo Next steps:
echo   • CLI:  wvs --help  or  wvs.bat --help  or  python main.py --help
echo   • UI:   Double-click ui.bat  (http://localhost:8501)
echo   • Scan: wvs --url http://localhost/dvwa --src C:\xampp\htdocs\dvwa --ai-provider openrouter
echo.
echo Free AI: OpenRouter (openrouter.ai/keys, no card) — 50 free req/day
echo          Groq (console.groq.com, 14k/day) also free.
echo.
pause
