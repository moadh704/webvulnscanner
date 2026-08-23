@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
echo ========================================
echo   WebVulnScanner - Installation
echo ========================================
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [1/4] Creating venv...
if not exist "venv\Scripts\python.exe" (
    python -m venv venv
)
call venv\Scripts\activate.bat >nul 2>&1
echo [2/4] Installing dependencies...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo [3/4] Installing wvs...
pip install -e . --quiet
echo [4/4] Checking config...
if not exist "config.py" (
    if exist "config.example.py" copy /y config.example.py config.py >nul
)
echo.
echo Installation complete!
echo   Run ui.bat for Web UI or wvs.bat --help for CLI
pause
