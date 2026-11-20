# IBVAP -- one container serves the API, the WebSockets and the dashboard
# from the same origin (no CORS or cross-origin WebSocket setup needed).
# Build from the repository root:
#   docker build -t ibvap .
#   docker run -p 8000:8000 -v ibvap-data:/app/data ibvap
# Add --build-arg WITH_YOLO=1 for YOLOv8 (bigger image, needs ~2 GB RAM).

FROM python:3.12-slim

ARG WITH_YOLO=0
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgl1 libglib2.0-0 tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt \
 && if [ "$WITH_YOLO" = "1" ]; then \
        pip install --no-cache-dir ultralytics \
     && pip install --no-cache-dir --force-reinstall --no-deps opencv-python-headless==4.13.0.92; \
    fi

COPY backend ./backend
COPY frontend ./frontend
# 960px demo clips shown under Video Sources (sized for small cloud CPUs)
COPY samples ./samples
RUN mkdir -p /app/data

ENV PYTHONPATH=/app/backend \
    IBVAP_DATA_DIR=/app/data \
    IBVAP_DETECTOR=auto
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD sh -c "python -c \"import urllib.request;urllib.request.urlopen('http://127.0.0.1:${PORT:-8000}/health')\""
# Frames are already-compressed JPEGs: WebSocket deflate would only burn CPU.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --ws-per-message-deflate false"]
