@echo off
REM Starts IBVAP and opens the dashboard. Run setup.bat once first.
title IBVAP
cd /d %~dp0
if not exist .venv (
    echo Run setup.bat first.
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
REM Set IBVAP_API_KEY before a public deployment. The dashboard uses the
REM documented demo key automatically and asks for a key only if it changed.
start "" cmd /c "timeout /t 4 >nul & start http://localhost:8000"
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --ws-per-message-deflate false
pause
