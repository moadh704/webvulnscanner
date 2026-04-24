@echo off
call venv\Scripts\activate.bat
echo ========================================
echo   WebVulnScanner - Ready
echo ========================================
echo.
echo Type your command, for example:
echo   WebVulnScanner --help
echo   WebVulnScanner --url http://localhost/dvwa --scan sqli
echo.
cmd /k