@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8

if not exist "venv\Scripts\activate.bat" (
    echo [INFO] No venv found — running setup...
    call setup.bat
    if errorlevel 1 exit /b 1
)
call venv\Scripts\activate.bat >nul 2>&1

:menu
cls
echo ========================================
echo   WebVulnScanner — Quick Menu
echo ========================================
echo.
echo   1. Show help              (wvs --help)
echo   2. No-AI scan (fast)      (DVWA, 21 endpoints)
echo   3. OpenRouter AI scan     (free, 41 findings)
echo   4. Open Web UI            (http://localhost:8501)
echo   5. Open last HTML report  (reports\)
echo   6. Exit
echo.
set /p choice="Choose [1-6]: "

if "%choice%"=="1" (
    wvs --help 2>nul || python -u main.py --help
    pause
    goto menu
)
if "%choice%"=="2" (
    echo.
    echo Running: wvs --url http://localhost/dvwa --src C:\xampp\htdocs\dvwa --difficulty low --no-ai --report-name quick_noai
    wvs --url http://localhost/dvwa --src C:\xampp\htdocs\dvwa --username admin --password password --difficulty low --no-ai --report-name quick_noai 2>nul || python -u main.py --url http://localhost/dvwa --src C:\xampp\htdocs\dvwa --username admin --password password --difficulty low --no-ai --report-name quick_noai
    pause
    goto menu
)
if "%choice%"=="3" (
    echo.
    echo Running: wvs --url http://localhost/dvwa --ai-provider openrouter (free)
    wvs --url http://localhost/dvwa --src C:\xampp\htdocs\dvwa --username admin --password password --difficulty low --ai-provider openrouter --report-name quick_openrouter 2>nul || python -u main.py --url http://localhost/dvwa --src C:\xampp\htdocs\dvwa --username admin --password password --difficulty low --ai-provider openrouter --report-name quick_openrouter
    pause
    goto menu
)
if "%choice%"=="4" (
    echo Starting Web UI...
    start "" "http://localhost:8501"
    python -m streamlit run app.py --server.port 8501
    pause
    goto menu
)
if "%choice%"=="5" (
    if exist "reports" (
        echo Opening reports folder...
        explorer reports
    ) else (
        echo No reports folder yet — run a scan first.
        pause
    )
    goto menu
)
if "%choice%"=="6" exit /b 0
goto menu
