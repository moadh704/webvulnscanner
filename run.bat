@echo off
call venv\Scripts\activate.bat
echo ========================================
echo   WebVulnScanner - Ready
echo ========================================
echo.
echo Type your command, for example:
echo   wvs --help
echo   wvs --url http://localhost/dvwa --scan sqli
echo.
cmd /k