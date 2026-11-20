"""
streams.py
----------
Stream workers: one processing loop per camera, any number of viewers.

The original design ran the pipeline inside each WebSocket handler, so two
browser tabs on the same camera advanced it twice as fast, and CPU-heavy
work blocked the event loop for every other client. Now each stream is a
StreamWorker: an asyncio task that runs the pipeline step in a worker thread
(asyncio.to_thread), encodes ONE payload per frame and fans it out to every
subscriber through a 2-slot queue (slow viewers drop frames, never stall the
camera). Simulated cameras start on first viewer and stop after
WORKER_IDLE_STOP_S with no viewers.

Sources
  SimSource    scripted scenario (simulator.py)
  VideoSource  uploaded or bundled video file, sampled to ~10 fps
  RTSPSource   real IP camera with reconnect (rtsp_source.py)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import cv2

from app.config import STREAM_FPS, WORKER_IDLE_STOP_S
from app.core.pipeline import CameraSession
from app.core.rtsp_source import close_rtsp_session, open_rtsp_session, read_frame_with_reconnect

logger = logging.getLogger("ibvap.streams")

# The demo site. map_x / map_y place each camera on the schematic site map
# used by the vehicle trajectory view (0-100 coordinate space).
SITE_CAMERAS: List[dict] = [
    {"id": "cam-01", "name": "North Fence - Sector 7", "post": "BOP Ranipur", "scenario": "fence",
     "map_x": 22, "map_y": 22},
    {"id": "cam-02", "name": "Check Post Alpha - ANPR Lane", "post": "ICP Gate 2", "scenario": "checkpost",
     "map_x": 70, "map_y": 30},
    {"id": "cam-03", "name": "River Crossing - BOP Gate", "post": "BOP Teesta", "scenario": "river",
     "map_x": 30, "map_y": 74},
    {"id": "cam-04", "name": "Perimeter Road East", "post": "Patrol Road 4", "scenario": "road",
     "map_x": 80, "map_y": 72},
]
CAMERA_INDEX = {c["id"]: c for c in SITE_CAMERAS}


class SimSource:
    kind = "simulated"

    def __init__(self, session: CameraSession):
        self.session = session

    def step(self):
        frame, tracks, alerts = self.session.step_simulation()
        return frame, tracks, alerts, {}

    def close(self):
        pass


class VideoSource:
    kind = "upload"

    def __init__(self, session: CameraSession, path: Path, target_fps: float = 10.0,
                 loop: bool = False, delete_on_close: bool = False, label: str = ""):
        self.cap = cv2.VideoCapture(str(path))
        if not self.cap.isOpened():
            raise ValueError("Could not open video -- unsupported codec or corrupt file")
        self.path, self.loop, self.delete_on_close, self.label = path, loop, delete_on_close, label
        self.src_fps = self.cap.get(cv2.CAP_PROP_FPS) or 25.0
        self.total = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        self.skip = max(1, round(self.src_fps / target_fps))
        w = int(self.cap.get(cv2.CAP_PROP_FRAME_WIDTH)) or 960
        h = int(self.cap.get(cv2.CAP_PROP_FRAME_HEIGHT)) or 540
        self.session = session
        session.source_kind = "upload"
        session.resize_for_source(w, h, self.src_fps / self.skip)
        self.pos = 0
        self.finished = False

    def step(self):
        frame = None
        for _ in range(self.skip):
            ok, f = self.cap.read()
            if not ok:
                frame = None
                break
            frame = f
            self.pos += 1
        if frame is None:
            if self.loop and self.pos > 0:
                self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                self.pos = 0
                self.session._init_tracking_state()
                return self.step()
            self.finished = True
            return None
        annotated, tracks, alerts = self.session.process_frame(frame)
        return annotated, tracks, alerts, {"progress": {"pos": self.pos, "total": self.total}, "label": self.label}

    def close(self):
        self.cap.release()
        if self.delete_on_close:
            self.path.unlink(missing_ok=True)


class RTSPSource:
    kind = "rtsp"

    def __init__(self, session: CameraSession, url: str):
        self.rtsp = open_rtsp_session(session.camera_id, url)
        self.session = session
        session.source_kind = "rtsp"
        self.finished = False

    def step(self):
        frame = read_frame_with_reconnect(self.rtsp)
        if frame is None:
            self.finished = True
            return None
        h, w = frame.shape[:2]
        if (w, h) != (self.session.frame_w, self.session.frame_h):
            self.session.resize_for_source(w, h, STREAM_FPS)
        annotated, tracks, alerts = self.session.process_frame(frame)
        return annotated, tracks, alerts, {}

    def close(self):
        close_rtsp_session(self.session.camera_id)


@dataclass
class StreamWorker:
    stream_id: str
    session: CameraSession
    source: object
    fps: float = STREAM_FPS
    persistent: bool = False      # simulated cameras auto-stop when idle; others end with their source
    subscribers: Set[asyncio.Queue] = field(default_factory=set)
    latest: Optional[str] = None
    task: Optional[asyncio.Task] = None
    started_at: float = field(default_factory=time.time)
    frames: int = 0
    fps_measured: float = 0.0
    last_viewer_at: float = field(default_factory=time.time)
    error: Optional[str] = None
    done: bool = False

    def info(self) -> dict:
        s = self.session
        return {"stream_id": self.stream_id, "camera_id": s.camera_id, "name": s.name, "source": self.source.kind,
                "running": self.task is not None and not self.task.done(), "viewers": len(self.subscribers),
                "frames": self.frames, "fps": round(self.fps_measured, 1), "step_ms": round(s.last_step_ms, 1),
                "detector": s.detector_name, "night_mode": s.night_mode, "done": self.done, "error": self.error}

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        self.subscribers.add(q)
        self.last_viewer_at = time.time()
        if self.latest:
            q.put_nowait(self.latest)
        self.ensure_running()
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)
        self.last_viewer_at = time.time()

    def ensure_running(self) -> None:
        if self.done:
            return
        if self.task is None or self.task.done():
            self.task = asyncio.get_running_loop().create_task(self._run())

    def _fanout(self, text: str) -> None:
        self.latest = text
        for q in list(self.subscribers):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(text)

    def _step(self) -> Optional[str]:
        out = self.source.step()
        if out is None:
            return None
        frame, tracks, alerts, extra = out
        payload = self.session.build_payload(frame, tracks, alerts, extra={"stream_id": self.stream_id, **extra})
        payload["fps"] = round(self.fps_measured, 1)
        return json.dumps(payload)

    async def _run(self) -> None:
        period = 1.0 / self.fps
        ema = None
        last = time.perf_counter()
        try:
            while True:
                if self.persistent and not self.subscribers and time.time() - self.last_viewer_at > WORKER_IDLE_STOP_S:
                    logger.info("Stream %s idle, pausing", self.stream_id)
                    return
                t0 = time.perf_counter()
                text = await asyncio.to_thread(self._step)
                if text is None:
                    self.done = True
                    self._fanout(json.dumps({"type": "done", "stream_id": self.stream_id,
                                             "camera_id": self.session.camera_id}))
                    # Free the video decoder now rather than when the worker is
                    # pruned; finished replays otherwise held tens of MB each.
                    await asyncio.to_thread(self.source.close)
                    return
                self.frames += 1
                now = time.perf_counter()
                inst = 1.0 / max(1e-3, now - last)
                last = now
                ema = inst if ema is None else 0.9 * ema + 0.1 * inst
                self.fps_measured = ema
                self._fanout(text)
                await asyncio.sleep(max(0.0, period - (time.perf_counter() - t0)))
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("Stream %s failed", self.stream_id)
            self.error = f"{type(e).__name__}: {e}"
            self._fanout(json.dumps({"type": "error", "stream_id": self.stream_id, "message": self.error}))

    async def stop(self) -> None:
        self.done = True
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        try:
            self.source.close()
        except Exception:  # noqa: BLE001
            pass


class StreamManager:
    def __init__(self) -> None:
        self.workers: Dict[str, StreamWorker] = {}
        self.sessions: Dict[str, CameraSession] = {}

    def session_for(self, camera_id: str) -> CameraSession:
        if camera_id not in self.sessions:
            cam = CAMERA_INDEX.get(camera_id)
            self.sessions[camera_id] = CameraSession(
                camera_id=camera_id, name=cam["name"] if cam else camera_id,
                scenario=cam["scenario"] if cam else None,
                source_kind="simulated" if cam else "upload")
        return self.sessions[camera_id]

    def sim_worker(self, camera_id: str) -> StreamWorker:
        w = self.workers.get(camera_id)
        if w is None or w.done:
            session = self.session_for(camera_id)
            session.source_kind = "simulated"
            w = StreamWorker(camera_id, session, SimSource(session), persistent=True)
            self.workers[camera_id] = w
        return w

    def get(self, stream_id: str) -> Optional[StreamWorker]:
        if stream_id in self.workers:
            return self.workers[stream_id]
        if stream_id in CAMERA_INDEX:
            return self.sim_worker(stream_id)
        return None

    async def start_video(self, path: Path, camera_id: str, label: str, delete_on_close: bool,
                          loop: bool = False) -> StreamWorker:
        stream_id = f"replay-{uuid.uuid4().hex[:8]}"
        session = CameraSession(camera_id=camera_id, name=label or camera_id, source_kind="upload")
        src = await asyncio.to_thread(VideoSource, session, path, 10.0, loop, delete_on_close, label)
        w = StreamWorker(stream_id, session, src, fps=10.0)
        self.workers[stream_id] = w
        self.sessions[camera_id] = session
        await self._prune()
        return w

    async def start_rtsp(self, camera_id: str, url: str) -> StreamWorker:
        session = CameraSession(camera_id=camera_id, name=camera_id, source_kind="rtsp")
        src = await asyncio.to_thread(RTSPSource, session, url)
        old = self.workers.get(camera_id)
        if old:
            await old.stop()
        w = StreamWorker(camera_id, session, src, fps=STREAM_FPS)
        self.workers[camera_id] = w
        self.sessions[camera_id] = session
        return w

    async def stop(self, stream_id: str) -> bool:
        w = self.workers.pop(stream_id, None)
        if w:
            await w.stop()
            return True
        return False

    async def _prune(self) -> None:
        """Keep at most 1 finished replay worker around (its last frame stays viewable)."""
        finished = [k for k, w in self.workers.items() if k.startswith("replay-") and w.done]
        for k in finished[:-1]:
            await self.stop(k)

    async def shutdown(self) -> None:
        for k in list(self.workers):
            await self.stop(k)


manager = StreamManager()
