"""Live streams: simulated site cameras, video replay, RTSP, and the
command-center event bus."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from app.config import REPLAY_DIR, SAMPLE_VIDEO_DIRS
from app.core.cross_camera import find_cross_camera_matches
from app.core.hub import hub
from app.core.pipeline import CameraSession
from app.core.streams import CAMERA_INDEX, SITE_CAMERAS, manager

router = APIRouter()

VIDEO_TYPES = ("video/mp4", "video/avi", "video/x-msvideo", "video/quicktime", "video/x-matroska",
               "video/webm", "application/octet-stream")
VIDEO_EXT = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".m4v"}


async def _pump(websocket: WebSocket, worker) -> None:
    q = worker.subscribe()
    try:
        while True:
            text = await q.get()
            await websocket.send_text(text)
            if text.startswith('{"type": "done"') or text.startswith('{"type": "error"'):
                break
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        worker.unsubscribe(q)


@router.websocket("/api/ws/stream/{stream_id}")
async def ws_stream(websocket: WebSocket, stream_id: str):
    await websocket.accept()
    worker = manager.get(stream_id)
    if worker is None:
        await websocket.send_json({"type": "error", "message": f"Unknown stream {stream_id!r}"})
        await websocket.close()
        return
    await _pump(websocket, worker)


@router.websocket("/api/ws/live/{camera_id}")
async def ws_live(websocket: WebSocket, camera_id: str):
    """Backward-compatible alias: any camera id becomes a simulated stream."""
    await websocket.accept()
    if camera_id not in CAMERA_INDEX:
        camera_id = "cam-01"
    await _pump(websocket, manager.sim_worker(camera_id))


@router.websocket("/api/ws/events")
async def ws_events(websocket: WebSocket):
    """Command-center bus: every alert from every camera, plus a threat and
    stream-health update every 2 seconds."""
    await websocket.accept()
    q = hub.subscribe()
    try:
        while True:
            await websocket.send_text(await q.get())
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(q)


@router.get("/api/cameras")
def list_cameras():
    out = []
    for c in SITE_CAMERAS:
        w = manager.workers.get(c["id"])
        out.append({**c, "stream": w.info() if w else None})
    return out


@router.get("/api/streams")
def list_streams():
    return [w.info() for w in manager.workers.values()]


@router.post("/api/streams/{stream_id}/stop")
async def stop_stream(stream_id: str):
    if not await manager.stop(stream_id):
        raise HTTPException(404, "No such stream")
    return {"status": "stopped", "stream_id": stream_id}


def _sample_files():
    files = []
    for d in SAMPLE_VIDEO_DIRS:
        if d.exists():
            files += [p for p in sorted(d.iterdir()) if p.suffix.lower() in VIDEO_EXT]
    return files


@router.get("/api/samples")
def list_samples():
    import cv2
    out = []
    for p in _sample_files():
        cap = cv2.VideoCapture(str(p))
        out.append({"name": p.name, "size_mb": round(p.stat().st_size / 1e6, 1),
                    "fps": round(cap.get(cv2.CAP_PROP_FPS) or 0, 1),
                    "frames": int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0),
                    "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0),
                    "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)})
        cap.release()
    return out


@router.post("/api/replay/sample")
async def replay_sample(name: str = Query(...), camera_id: str = Query("cam-replay"), loop: bool = Query(False)):
    match = next((p for p in _sample_files() if p.name == name), None)
    if match is None:
        raise HTTPException(404, f"No sample video named {name!r}")
    try:
        w = await manager.start_video(match, camera_id, f"Replay - {name}", delete_on_close=False, loop=loop)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"stream_id": w.stream_id, "camera_id": camera_id, "total_frames": w.source.total,
            "fps": w.source.src_fps}


@router.post("/api/replay/start")
async def start_replay(camera_id: str = Query("cam-replay"), file: UploadFile = File(...)):
    suffix = Path(file.filename or "upload.mp4").suffix.lower() or ".mp4"
    if file.content_type not in VIDEO_TYPES and suffix not in VIDEO_EXT:
        raise HTTPException(400, f"Unsupported content type: {file.content_type}")
    REPLAY_DIR.mkdir(parents=True, exist_ok=True)
    dest = REPLAY_DIR / f"{uuid.uuid4().hex[:12]}{suffix}"
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    try:
        w = await manager.start_video(dest, camera_id, f"Replay - {file.filename}", delete_on_close=True)
    except ValueError as e:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, str(e))
    return {"stream_id": w.stream_id, "session_id": w.stream_id, "camera_id": camera_id,
            "total_frames": w.source.total, "fps": w.source.src_fps}


@router.websocket("/api/ws/replay/{session_id}")
async def ws_replay(websocket: WebSocket, session_id: str):
    await ws_stream(websocket, session_id)


@router.post("/api/upload")
async def upload_video(camera_id: str = Query("cam-upload"), file: UploadFile = File(...)):
    """Batch analysis of a whole video; returns a JSON report (no live view)."""
    suffix = Path(file.filename or "upload.mp4").suffix or ".mp4"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name
    try:
        session = CameraSession(camera_id=camera_id, source_kind="upload")
        report = await asyncio.to_thread(session.process_upload, tmp_path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"Processing failed: {type(e).__name__}: {e}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return JSONResponse(report)


@router.post("/api/live/rtsp/connect")
async def rtsp_connect(camera_id: str = Query(...), rtsp_url: str = Query(...)):
    try:
        w = await manager.start_rtsp(camera_id, rtsp_url)
    except ConnectionError as e:
        raise HTTPException(502, str(e))
    return {"status": "connected", "camera_id": camera_id, "stream_id": w.stream_id}


@router.post("/api/live/rtsp/disconnect")
async def rtsp_disconnect(camera_id: str = Query(...)):
    await manager.stop(camera_id)
    return {"status": "disconnected", "camera_id": camera_id}


@router.websocket("/api/ws/live-rtsp/{camera_id}")
async def ws_live_rtsp(websocket: WebSocket, camera_id: str):
    await ws_stream(websocket, camera_id)


@router.get("/api/streams/{camera_id}/heatmap")
def heatmap(camera_id: str):
    s = manager.sessions.get(camera_id)
    if s is None:
        raise HTTPException(404, "No session for this camera yet -- open its stream first.")
    return {"camera_id": camera_id, **s.heatmap()}


@router.get("/api/cross-camera/match")
def cross_camera_match(camera_a: str = Query(...), camera_b: str = Query(...), threshold: float = Query(0.65)):
    if camera_a == camera_b:
        raise HTTPException(400, "camera_a and camera_b must be different sessions.")
    a, b = manager.session_for(camera_a), manager.session_for(camera_b)
    ta = list(a.tracker.tracks.values()) + list(a.vehicle_tracker.tracks.values())
    tb = list(b.tracker.tracks.values()) + list(b.vehicle_tracker.tracks.values())
    matches = find_cross_camera_matches(camera_a, a._last_frame, ta, camera_b, b._last_frame, tb, threshold)
    return {"camera_a": camera_a, "camera_b": camera_b, "threshold": threshold,
            "matches": [m.__dict__ for m in matches],
            "note": "HSV colour-histogram heuristic, not deep re-identification."}


def session_or_none(camera_id: str) -> Optional[CameraSession]:
    return manager.sessions.get(camera_id)
