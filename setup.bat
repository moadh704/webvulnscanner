@echo off
echo ========================================
echo   WebVulnScanner - Installation
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
) else (
    echo       venv already exists, skipping.
)

echo.
echo [2/3] Installing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt --quiet --disable-pip-version-check

echo.
echo [3/3] Installing WebVulnScanner command...
pip install -e . --quiet --disable-pip-version-check

echo.
echo ========================================
echo   Installation complete!
echo ========================================
echo.
echo To run WebVulnScanner:
echo   Double-click run.bat
echo.
echo Or from command line:
echo   1. venv\Scripts\activate
echo   2. WebVulnScanner --help
echo.
pause