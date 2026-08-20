@echo off
REM wvs.bat - Quick launcher for WebVulnScanner
REM Works without pip-install: just run from the project folder.
cd /d "%~dp0"
call venv\Scripts\activate.bat >nul 2>&1
python -u main.py %*
