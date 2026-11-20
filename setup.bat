@echo off
REM IBVAP one-time setup (Windows). Run from the repository root.
cd /d %~dp0
echo === IBVAP setup ===
if not exist .venv (
    python -m venv .venv || (echo Python 3.11+ is required on PATH & pause & exit /b 1)
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r backend\requirements.txt || (echo Dependency install failed & pause & exit /b 1)

echo.
echo Installing YOLOv8 (recommended for real footage)...
pip install ultralytics
echo Restoring the headless OpenCV build that ultralytics replaces...
pip install --force-reinstall --no-deps opencv-python-headless==4.13.0.92

echo.
where tesseract >nul 2>nul || if not exist "C:\Program Files\Tesseract-OCR\tesseract.exe" (
    echo NOTE: Tesseract OCR not found. ANPR on real footage needs it:
    echo       https://github.com/UB-Mannheim/tesseract/wiki
)
echo.
echo === Setup complete. Start IBVAP with run.bat ===
pause
