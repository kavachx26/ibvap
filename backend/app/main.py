"""
main.py
-------
IBVAP - Intelligent Border Video Analytics Platform (v3, CodeQuest 2026 final).

Run (from backend/):
    uvicorn app.main:app --host 0.0.0.0 --port 8000
Dashboard: http://localhost:8000      API docs: http://localhost:8000/docs

Routers
  app.api.streams    live site cameras, replay, RTSP, command-center bus
  app.api.incidents  alert queue, workflow, evidence frames, signed bundles, reports
  app.api.intel      ANPR sightings, trajectories, watchlist, event log
  app.api.audit      chain verification, explorer, checkpoints, tamper demo
  app.api.analytics  KPIs, timeline, threat level, zones, system status, shift briefing
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api import analytics, audit, incidents, intel, streams
from app.config import (API_KEY, APP_FULL_NAME, APP_NAME, APP_VERSION, CV_THREADS, DETECTOR_BACKEND,
                        FRONTEND_DIR, REPLAY_DIR)
from app.core.detector import shared_yolo, yolo_available
from app.core.hub import hub
from app.core.storage import init_db
from app.core.streams import manager

log = logging.getLogger("ibvap")


class APIKeyMiddleware:
    """Raw ASGI middleware so it also guards WebSocket handshakes
    (BaseHTTPMiddleware never sees them). Key via X-API-Key header, or
    ?api_key= for WebSockets and links (browsers cannot set headers there).
    "/", "/static" and "/health" stay open."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket") or not scope.get("path", "").startswith("/api/"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        supplied = headers.get(b"x-api-key", b"").decode()
        if not supplied:
            supplied = (parse_qs(scope.get("query_string", b"").decode()).get("api_key") or [""])[0]
        if supplied != API_KEY:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401})
            else:
                await JSONResponse({"detail": "Invalid or missing API key (X-API-Key header or ?api_key=)."},
                                   status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)


async def _threat_broadcaster():
    while True:
        try:
            snap = await asyncio.to_thread(analytics.threat_snapshot)
            hub.publish({"type": "threat", **snap, "streams": [w.info() for w in manager.workers.values()]})
        except Exception:  # noqa: BLE001
            log.exception("threat broadcast failed")
        await asyncio.sleep(2.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if CV_THREADS > 0:
        import cv2
        cv2.setNumThreads(CV_THREADS)
    init_db()
    REPLAY_DIR.mkdir(parents=True, exist_ok=True)
    loop = asyncio.get_running_loop()
    hub.bind_loop(loop)

    def _quiet_resets(lp, ctx):
        # Windows' proactor loop logs a traceback whenever a browser tab
        # closes its socket abruptly. That is normal, not an error.
        if isinstance(ctx.get("exception"), ConnectionResetError):
            return
        lp.default_exception_handler(ctx)
    loop.set_exception_handler(_quiet_resets)

    task = asyncio.create_task(_threat_broadcaster())
    if DETECTOR_BACKEND != "hog" and yolo_available():
        # Load YOLOv8 now (in a thread) so the first real video starts at
        # once instead of stalling ~8 s while torch imports mid-demo.
        loop.run_in_executor(None, shared_yolo)
    log.info("%s %s ready", APP_NAME, APP_VERSION)
    yield
    task.cancel()
    await manager.shutdown()


app = FastAPI(
    title=f"{APP_NAME} API",
    version=APP_VERSION,
    description=(f"{APP_FULL_NAME}: AI video analytics for existing border CCTV. People and vehicle "
                 "detection and tracking, ANPR with OCR-tolerant watchlist matching, virtual-fence "
                 "intrusion, loitering, group/convoy and erratic-motion detection, night-time "
                 "enhancement, a per-camera threat level, an incident workflow with chain of custody, "
                 "and tamper-evident evidence (SHA-256 hash chain + Ed25519-signed checkpoints and "
                 "evidence bundles). All /api routes need the X-API-Key header."),
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=2048)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(APIKeyMiddleware)

for r in (streams.router, incidents.router, intel.router, audit.router, analytics.router):
    app.include_router(r)

if (FRONTEND_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def index():
    page = FRONTEND_DIR / "index.html"
    if page.exists():
        return FileResponse(page, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"detail": "Frontend not bundled. API docs at /docs."}, status_code=404)
