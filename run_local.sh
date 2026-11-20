#!/usr/bin/env bash
# IBVAP quick start (Linux / macOS). Needs Python 3.11+ and, for ANPR on
# real footage, the tesseract binary (apt install tesseract-ocr / brew install tesseract).
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  . .venv/bin/activate
  pip install -q -r backend/requirements.txt
  if [ "${WITH_YOLO:-1}" = "1" ]; then
    pip install -q ultralytics
    pip install -q --force-reinstall --no-deps opencv-python-headless==4.13.0.92
  fi
else
  . .venv/bin/activate
fi
echo "IBVAP on http://localhost:8000  (API docs: /docs)"
exec python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --ws-per-message-deflate false
