"""
config.py
---------
One place for every path and setting. Values come from environment variables
so the same build runs on a laptop, in Docker or on a free cloud host.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "IBVAP"
APP_FULL_NAME = "Intelligent Border Video Analytics Platform"
APP_VERSION = "3.0.0"
TEAM_NAME = "Team KavachX"

ROOT_DIR = Path(__file__).resolve().parents[2]          # sentinel-grid/
DATA_DIR = Path(os.environ.get("IBVAP_DATA_DIR", ROOT_DIR / "data"))
DB_PATH = DATA_DIR / "ibvap.db"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
REPLAY_DIR = DATA_DIR / "replay_uploads"
KEYS_DIR = DATA_DIR / "keys"
FRONTEND_DIR = ROOT_DIR / "frontend"
SAMPLE_VIDEO_DIRS = [ROOT_DIR / "samples", ROOT_DIR / "project_documents"]

# Shared API key for every /api/* route (HTTP header X-API-Key, or ?api_key=
# for WebSockets and links). Override before any public deployment.
API_KEY = os.environ.get("IBVAP_API_KEY", "ibvap-demo-key-2026-CHANGE-ME")

# "auto" uses YOLOv8 for real footage when ultralytics + weights are present,
# otherwise the offline HOG/MOG2 floor. "hog" forces the offline floor.
DETECTOR_BACKEND = os.environ.get("IBVAP_DETECTOR", "auto")
YOLO_WEIGHTS = os.environ.get("IBVAP_YOLO_WEIGHTS", str(ROOT_DIR / "backend" / "yolov8n.pt"))

STREAM_FPS = float(os.environ.get("IBVAP_STREAM_FPS", "12"))
# A signed checkpoint is written after this many new audit records.
CHECKPOINT_EVERY = int(os.environ.get("IBVAP_CHECKPOINT_EVERY", "25"))
# Small-host tuning (used on Render's free plan: 0.1 CPU, 512 MB RAM).
# CV_THREADS > 0 caps OpenCV's worker threads (each holds its own buffers).
# HOG_MAX_DIM is the frame size the offline person detector works at, and
# HOG_EVERY runs it on every Nth frame (tracks carry the boxes in between).
CV_THREADS = int(os.environ.get("IBVAP_CV_THREADS", "0"))
HOG_MAX_DIM = int(os.environ.get("IBVAP_HOG_MAX_DIM", "720"))
HOG_EVERY = max(1, int(os.environ.get("IBVAP_HOG_EVERY", "1")))
# ANPR effort: "full" (up to 5 plate candidates x 3 binarisations x 2 page
# modes, 6 attempts per vehicle), "lite" (2 candidates, 1 pass, 2 attempts:
# each Tesseract call is a separate process, too costly on a 0.1-CPU host),
# or "off".
ANPR_MODE = os.environ.get("IBVAP_ANPR_MODE", "full").lower()
# Simulated camera workers stop this many seconds after their last viewer leaves.
WORKER_IDLE_STOP_S = float(os.environ.get("IBVAP_WORKER_IDLE_STOP_S", "45"))
