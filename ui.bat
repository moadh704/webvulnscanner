@echo off
call venv\Scripts\activate.bat
echo ========================================
echo   WebVulnScanner - Web UI
echo ========================================
echo.
echo Starting Streamlit server...
echo The UI will open in your browser at:
echo   http://localhost:8501
echo.
echo Press Ctrl+C to stop the server.
echo.
streamlit run app.py