@echo off
REM wvs.bat - Quick launcher for WebVulnScanner (no shell injection, UTF-8 safe)
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

REM Prefer the installed entry point if available
where wvs >nul 2>&1
if not errorlevel 1 (
    wvs %*
    exit /b %errorlevel%
)

REM Fallback: use venv python or system python
if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -u main.py %*
) else (
    python -u main.py %*
)
