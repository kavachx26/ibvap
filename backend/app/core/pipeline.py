"""
pipeline.py
-----------
One CameraSession per camera feed. Every source (scripted simulation,
uploaded video, RTSP camera) goes through the same stages:

  frame -> night check (LAB brightness) -> CLAHE enhancement when dark
        -> detection (YOLOv8 one pass for people + vehicles, or HOG/MOG2 floor)
        -> two Hungarian centroid trackers (people, vehicles)
        -> behaviour analytics: loitering, unauthorized crossing, group /
           convoy (DBSCAN), erratic motion, night movement
        -> face detection on person crops (real footage)
        -> ANPR on vehicle crops (background thread) -> plate repair ->
           OCR-tolerant watchlist match -> watchlist alert
        -> heatmap accumulation
        -> annotated frame + evidence snapshot + hash-chained storage

In simulation the detector is replaced by scripted detections (see
simulator.py); everything after detection is identical, so the analytics a
judge sees in the demo are exactly what runs on real footage.
"""

from __future__ import annotations

import base64
import collections
import threading
import time
from typing import Deque, Dict, List, Optional, Tuple

import cv2
import numpy as np

from app.config import ANPR_MODE, DETECTOR_BACKEND, STREAM_FPS
from app.core import plates as plate_utils
from app.core.analytics import Alert, GroupBehaviorAnalyzer
from app.core.anpr import PlateRead, anpr_service
from app.core.detector import build_frame_detector
from app.core.face import FaceDetector
from app.core.night import enhance_for_detection, frame_brightness, is_night
from app.core.simulator import apply_night, build_scenario, draw_actor, frame_detections
from app.core.storage import (
    load_zones, save_alert, save_event, save_sighting, save_snapshot_file, save_stat,
    watchlist_entry, watchlist_plates,
)
from app.core.tracker import CentroidTracker, Track
from app.core.zones import BorderLine, Zone, default_demo_geometry

HEAT_W, HEAT_H = 48, 27
PROC_MAX_DIM = 1600
MAX_OCR_ATTEMPTS = 2 if ANPR_MODE == "lite" else 6

# BGR colours for on-frame overlays
C_PERSON = (90, 220, 120)
C_VEHICLE = (255, 196, 70)
C_ZONE = (60, 60, 235)
C_LINE = (40, 40, 255)
C_WATCH = (60, 30, 255)
SEV_COLORS = {"low": (200, 200, 200), "medium": (0, 200, 255), "high": (0, 140, 255), "critical": (40, 40, 255)}


def is_valid_indian_plate_format(text: str) -> bool:  # kept for backward compatibility
    return plate_utils.is_valid_format(text)


class CameraSession:
    def __init__(self, camera_id: str = "cam-01", name: Optional[str] = None,
                 scenario: Optional[str] = None, frame_w: int = 960, frame_h: int = 540,
                 detector_backend: str = DETECTOR_BACKEND, fps: float = STREAM_FPS,
                 source_kind: str = "simulated"):
        self.camera_id = camera_id
        self.name = name or camera_id
        self.source_kind = source_kind
        self.frame_w, self.frame_h = frame_w, frame_h
        self.fps = fps
        self._detector_backend = detector_backend
        self._detector = None
        self.scenario = build_scenario(scenario, frame_w, frame_h) if scenario else None
        self.zones: List[Zone] = []
        self.lines: List[BorderLine] = []
        self._load_geometry()

        self.face_detector = FaceDetector()
        self.heat = np.zeros((HEAT_H, HEAT_W), dtype=np.float32)
        self._lock = threading.Lock()
        self._pending_alerts: Deque[Alert] = collections.deque(maxlen=50)
        self.total_alerts_fired = 0
        self.total_events_logged = 0
        self.loop_index = 0
        self.night_mode = False
        self.brightness = 0.0
        self.last_step_ms = 0.0
        self._last_frame: Optional[np.ndarray] = None
        self._last_stat_frame = -999
        self._init_tracking_state()

    # ---- state ------------------------------------------------------
    def _init_tracking_state(self) -> None:
        # Every pixel threshold was tuned at 960 px width; scale to the real
        # frame so a 1080p or 4K camera behaves the same.
        k = max(0.5, self.frame_w / 960.0)
        self.frame_index = 0
        self.tracker = CentroidTracker(max_distance=90.0 * k)
        self.analyzer = GroupBehaviorAnalyzer(group_eps_px=80.0 * k, erratic_speed_px_s=260.0 * k)
        self.vehicle_tracker = CentroidTracker(max_distance=140.0 * k)
        eps = self.scenario.vehicle_group_eps if getattr(self, "scenario", None) else 200.0
        self.vehicle_analyzer = GroupBehaviorAnalyzer(
            group_min_size=2, group_persist_seconds=2.0, erratic_speed_px_s=550.0 * k,
            loiter_seconds=10.0, group_eps_px=eps * k,
        )
        self._plate_cache: Dict[int, str] = {}
        self._ocr_attempts: Dict[int, int] = {}
        self._ocr_last: Dict[int, int] = {}
        self._ocr_pending: set = set()
        self._face_cooldown: Dict[int, float] = {}
        self._detection_logged: set = set()

    def _load_geometry(self) -> None:
        saved = load_zones(self.camera_id)
        if saved:
            self.zones = [Zone(i + 1, z["name"], [tuple(p) for p in z["polygon"]], z.get("zone_type", "restricted"))
                          for i, z in enumerate(saved.get("zones", []))]
            self.lines = [BorderLine(i + 1, l["name"], tuple(l["p1"]), tuple(l["p2"]), l.get("unauthorized_side", "a_to_b"))
                          for i, l in enumerate(saved.get("lines", []))]
            if self.zones or self.lines:
                return
        if self.scenario:
            self.zones, self.lines = list(self.scenario.zones), list(self.scenario.lines)
        else:
            self.zones, self.lines = default_demo_geometry(self.frame_w, self.frame_h)

    def resize_for_source(self, w: int, h: int, fps: float) -> None:
        # Process at most PROC_MAX_DIM on the long side. A 4K/8MP frame cost
        # ~250 ms per frame in colour conversion and copies alone, and YOLO
        # resizes to 640 internally anyway.
        if max(w, h) > PROC_MAX_DIM:
            k = PROC_MAX_DIM / max(w, h)
            w, h = int(w * k), int(h * k)
        if (w, h) != (self.frame_w, self.frame_h):
            self.frame_w, self.frame_h = w, h
            self._load_geometry()
            if not load_zones(self.camera_id):
                self.zones, self.lines = default_demo_geometry(w, h)
        self.fps = fps
        self._init_tracking_state()

    def geometry_dict(self) -> dict:
        return {
            "frame_w": self.frame_w, "frame_h": self.frame_h,
            "zones": [{"zone_id": z.zone_id, "name": z.name, "polygon": [list(p) for p in z.polygon],
                       "zone_type": z.zone_type} for z in self.zones],
            "lines": [{"line_id": l.line_id, "name": l.name, "p1": list(l.p1), "p2": list(l.p2),
                       "unauthorized_side": l.unauthorized_side} for l in self.lines],
        }

    @property
    def detector(self):
        if self._detector is None:
            self._detector = build_frame_detector(self._detector_backend)
        return self._detector

    @property
    def detector_name(self) -> str:
        if self.source_kind == "simulated":
            return "Scripted scenario (simulation)"
        return getattr(self._detector, "name", "not loaded yet")

    def _vt(self) -> float:
        return self.frame_index / max(0.1, self.fps)

    # ---- simulation -------------------------------------------------
    def step_simulation(self) -> Tuple[np.ndarray, List[Track], List[Alert]]:
        t0 = time.perf_counter()
        sc = self.scenario or build_scenario("fence", self.frame_w, self.frame_h)
        self.scenario = sc
        f = self.frame_index
        vt = self._vt()
        night = sc.is_night(f)

        canvas = sc.background.copy()
        dets = frame_detections(sc.actors, f)
        for d, a in dets:
            plate = sc.plate_for(a.plate_slot, self.loop_index) if a.plate_slot is not None else None
            draw_actor(canvas, a, ((d.x1 + d.x2) / 2, d.y2 if a.label == "person" else (d.y1 + d.y2) / 2), plate, night)
        if night:
            canvas = apply_night(canvas, f)
        self.night_mode, self.brightness = night, (18.0 if night else 92.0)

        person_tracks = self.tracker.update([d for d, a in dets if a.label == "person"], timestamp=vt)
        vehicle_tracks = self.vehicle_tracker.update([d for d, a in dets if a.label == "vehicle"], timestamp=vt)
        alerts = self._run_analytics(person_tracks, vehicle_tracks, vt, night)

        vehicle_actors = [(d, a) for d, a in dets if a.label == "vehicle"]
        for t in vehicle_tracks:
            if t.track_id in self._plate_cache or t.misses or not vehicle_actors:
                continue
            x1, _, x2, _ = t.bbox
            if x1 < 4 or x2 > self.frame_w - 4:
                continue  # like a real camera, the plate is read once the vehicle is fully in view
            d, a = min(vehicle_actors, key=lambda da: (da[0].centroid[0] - t.centroid[0]) ** 2
                       + (da[0].centroid[1] - t.centroid[1]) ** 2)
            plate = sc.plate_for(a.plate_slot, self.loop_index)
            alerts += self._apply_plate(t, plate, plate, 0.99, "simulated", vt)

        self._log_new_detections(person_tracks, vt)
        self._log_new_detections(vehicle_tracks, vt)
        self._accumulate_heat(person_tracks + vehicle_tracks)

        self._draw_overlays(canvas, person_tracks, vehicle_tracks, alerts, night)
        self._persist(alerts, len(person_tracks), len(vehicle_tracks), canvas)
        alerts += self._drain_pending()

        self.frame_index += 1
        if self.frame_index >= sc.loop_frames:
            self.loop_index += 1
            self._init_tracking_state()
        self._last_frame = canvas
        self.last_step_ms = (time.perf_counter() - t0) * 1000
        return canvas, person_tracks + vehicle_tracks, alerts

    # ---- real footage -----------------------------------------------
    def process_frame(self, frame: np.ndarray) -> Tuple[np.ndarray, List[Track], List[Alert]]:
        t0 = time.perf_counter()
        vt = self._vt()
        if frame.ndim == 3 and (frame.shape[1], frame.shape[0]) != (self.frame_w, self.frame_h):
            if max(frame.shape[:2]) > PROC_MAX_DIM:
                frame = cv2.resize(frame, (self.frame_w, self.frame_h), interpolation=cv2.INTER_AREA)
            else:
                self.resize_for_source(frame.shape[1], frame.shape[0], self.fps)
        thumb = cv2.resize(frame, (160, 90), interpolation=cv2.INTER_AREA) if frame.ndim == 3 else frame
        if frame.ndim != 3 or float(thumb.std()) < 3.0:
            annotated = frame.copy() if frame.ndim == 3 else cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
            cv2.putText(annotated, "LOW-SIGNAL FRAME - analysis skipped", (12, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2, cv2.LINE_AA)
            self.frame_index += 1
            return annotated, [], []

        self.brightness = frame_brightness(thumb)
        night = is_night(thumb)
        self.night_mode = night
        detect_input = enhance_for_detection(frame) if night else frame
        persons, vehicles = self.detector.detect(detect_input)
        person_tracks = self.tracker.update(persons, timestamp=vt)
        vehicle_tracks = self.vehicle_tracker.update(vehicles, timestamp=vt)
        alerts = self._run_analytics(person_tracks, vehicle_tracks, vt, night)

        self._detect_faces(person_tracks, frame, vt)
        self._schedule_ocr(vehicle_tracks, frame, vt)
        self._log_new_detections(person_tracks, vt)
        self._log_new_detections(vehicle_tracks, vt)
        self._accumulate_heat(person_tracks + vehicle_tracks)

        annotated = detect_input.copy() if night else frame.copy()
        self._draw_overlays(annotated, person_tracks, vehicle_tracks, alerts, night)
        self._persist(alerts, len(person_tracks), len(vehicle_tracks), annotated)
        alerts += self._drain_pending()
        self.frame_index += 1
        self._last_frame = annotated
        self.last_step_ms = (time.perf_counter() - t0) * 1000
        return annotated, person_tracks + vehicle_tracks, alerts

    def process_upload(self, path: str, sample_every: int = 2, max_frames: int = 600) -> dict:
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            raise ValueError("Could not open uploaded video")
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)) or self.frame_w
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)) or self.frame_h
        src_fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        self.source_kind = "upload"
        self.resize_for_source(w, h, src_fps / sample_every)
        all_alerts: List[Alert] = []
        processed = idx = 0
        while processed < max_frames:
            ok, frame = cap.read()
            if not ok:
                break
            if idx % sample_every == 0:
                _, _, alerts = self.process_frame(frame)
                all_alerts.extend(alerts)
                processed += 1
            idx += 1
        cap.release()
        deadline = time.time() + 8
        while self._ocr_pending and time.time() < deadline:
            time.sleep(0.1)
        all_alerts.extend(self._drain_pending())
        return {
            "frames_processed": processed, "alerts_raised": len(all_alerts),
            "events_logged": self.total_events_logged,
            "plates_read": sorted(set(self._plate_cache.values())),
            "alerts": [{"type": a.alert_type, "severity": a.severity, "message": a.message,
                        "track_ids": a.track_ids, "timestamp": a.timestamp} for a in all_alerts],
        }

    # ---- analytics --------------------------------------------------
    def _run_analytics(self, person_tracks, vehicle_tracks, vt, night: bool) -> List[Alert]:
        alerts = self.analyzer.analyze(person_tracks, self.zones, self.lines, self.camera_id, timestamp=vt)
        alerts += self.vehicle_analyzer.analyze(vehicle_tracks, self.zones, self.lines, self.camera_id, timestamp=vt)
        if night:
            alerts += self.analyzer.check_night_movement(person_tracks, self.camera_id, vt, self.zones)
            alerts += self.vehicle_analyzer.check_night_movement(vehicle_tracks, self.camera_id, vt, self.zones)
        return alerts

    def _apply_plate(self, t: Track, text: str, raw: str, conf: float, engine: str, vt: float) -> List[Alert]:
        plate = plate_utils.repair(plate_utils.clean(text))
        valid = plate_utils.is_valid_format(plate)
        self._plate_cache[t.track_id] = plate
        match = plate_utils.match_watchlist(plate, watchlist_plates())
        wp, mtype = match if match else (None, None)
        source = "simulated" if engine == "simulated" else "ocr"
        save_sighting(plate, raw, self.camera_id, t.track_id, conf, source, valid, wp, mtype)
        save_event("anpr_read", self.camera_id,
                   f"{t.label.capitalize()} #{t.track_id} plate {plate} "
                   f"[{engine}, {'format verified' if valid else 'format unverified'}]", vt)
        self.total_events_logged += 1
        if not wp:
            return []
        entry = watchlist_entry(wp) or {"priority": "high", "reason": "watchlist"}
        reason = entry["reason"] if len(entry["reason"]) <= 70 else entry["reason"][:67] + "..."
        how = "" if mtype == "exact" else f" (read as {plate}, {mtype.replace('_', '-')} match)"
        return [Alert("watchlist_match", "critical" if entry["priority"] == "critical" else "high",
                      f"Watchlisted vehicle {wp} sighted{how}: {reason}", [t.track_id], vt,
                      self.camera_id, t.centroid, plate=wp)]

    def _schedule_ocr(self, vehicle_tracks: List[Track], frame: np.ndarray, vt: float) -> None:
        h, w = frame.shape[:2]
        for t in vehicle_tracks:
            tid = t.track_id
            if tid in self._plate_cache or tid in self._ocr_pending or t.misses:
                continue
            if self._ocr_attempts.get(tid, 0) >= MAX_OCR_ATTEMPTS or self.frame_index - self._ocr_last.get(tid, -99) < 6:
                continue
            x1, y1, x2, y2 = t.bbox
            if x2 - x1 < 70 or y2 - y1 < 40:
                continue
            pad_x, pad_y = int(0.05 * (x2 - x1)), int(0.05 * (y2 - y1))
            crop = frame[max(0, y1 - pad_y):min(h, y2 + pad_y), max(0, x1 - pad_x):min(w, x2 + pad_x)].copy()
            self._ocr_attempts[tid] = self._ocr_attempts.get(tid, 0) + 1
            self._ocr_last[tid] = self.frame_index
            self._ocr_pending.add(tid)
            track_snapshot = Track(t.track_id, t.centroid, t.bbox, t.label, t.first_seen, t.last_seen)
            if not anpr_service.submit(crop, lambda res, tr=track_snapshot, v=vt: self._on_ocr(tr, res, v)):
                self._ocr_pending.discard(tid)

    def _on_ocr(self, t: Track, res: Optional[PlateRead], vt: float) -> None:
        self._ocr_pending.discard(t.track_id)
        if res is None or not (res.format_valid or res.confidence >= 0.6):
            return
        alerts = self._apply_plate(t, res.text, res.raw_ocr, res.confidence, res.engine, vt)
        if alerts:
            evidence = self._last_frame if self._last_frame is not None else None
            self._persist(alerts, None, None, evidence)
            with self._lock:
                self._pending_alerts.extend(alerts)

    def _drain_pending(self) -> List[Alert]:
        with self._lock:
            out = list(self._pending_alerts)
            self._pending_alerts.clear()
        return out

    def _detect_faces(self, person_tracks: List[Track], frame: np.ndarray, vt: float) -> None:
        # Haar on every person crop every frame cost ~150 ms in crowds. Faces
        # need resolution anyway: run every 3rd frame on the 6 largest people.
        if self.frame_index % 3:
            return
        min_h = 80 * max(0.5, self.frame_w / 960.0)
        cands = [t for t in person_tracks if not t.misses and (t.bbox[3] - t.bbox[1]) >= min_h]
        cands.sort(key=lambda t: -(t.bbox[3] - t.bbox[1]))
        for t in cands[:6]:
            last = self._face_cooldown.get(t.track_id)
            if last is not None and vt - last < 15.0:
                continue
            x1, y1, x2, y2 = t.bbox
            x1, y1 = max(0, x1), max(0, y1)
            crop = frame[y1:max(y1 + 1, y1 + (y2 - y1) // 2), x1:x2]  # faces are in the upper half
            if crop.size == 0 or crop.shape[0] < 24:
                continue
            if crop.shape[0] > 160:
                k = 160 / crop.shape[0]
                crop = cv2.resize(crop, (max(1, int(crop.shape[1] * k)), 160), interpolation=cv2.INTER_AREA)
            if self.face_detector.detect(crop):
                self._face_cooldown[t.track_id] = vt
                save_event("face_detected", self.camera_id, f"Face detected on person #{t.track_id}", vt)
                self.total_events_logged += 1

    def _log_new_detections(self, tracks: List[Track], vt: float) -> None:
        for t in tracks:
            key = (t.label, t.track_id)
            if key in self._detection_logged:
                continue
            self._detection_logged.add(key)
            save_event(f"{'person' if t.label == 'person' else 'vehicle'}_detected", self.camera_id,
                       f"{t.label.capitalize()} #{t.track_id} detected", vt)
            self.total_events_logged += 1

    def _accumulate_heat(self, tracks: List[Track]) -> None:
        self.heat *= 0.9995
        for t in tracks:
            cx = int(min(HEAT_W - 1, max(0, t.centroid[0] / self.frame_w * HEAT_W)))
            cy = int(min(HEAT_H - 1, max(0, t.centroid[1] / self.frame_h * HEAT_H)))
            self.heat[cy, cx] += 1.0

    def heatmap(self) -> dict:
        m = float(self.heat.max()) or 1.0
        return {"w": HEAT_W, "h": HEAT_H, "max": m, "grid": np.round(self.heat / m, 3).tolist()}

    def _persist(self, alerts: List[Alert], people: Optional[int], vehicles: Optional[int],
                 evidence_frame: Optional[np.ndarray]) -> None:
        snapshot_hash = None
        if alerts and evidence_frame is not None:
            ok, buf = cv2.imencode(".jpg", evidence_frame, [int(cv2.IMWRITE_JPEG_QUALITY), 88])
            if ok:
                snapshot_hash = save_snapshot_file(buf.tobytes())
        for a in alerts:
            a.id = save_alert(a, snapshot_hash=snapshot_hash)
            a.snapshot_hash = snapshot_hash
            self.total_alerts_fired += 1
        if people is not None and self.frame_index - self._last_stat_frame >= max(1, int(self.fps)):
            self._last_stat_frame = self.frame_index
            save_stat(self.camera_id, people + (vehicles or 0), self.frame_index,
                      vehicle_count=vehicles or 0, night_mode=self.night_mode)

    # ---- overlays ---------------------------------------------------
    def _draw_overlays(self, frame, person_tracks, vehicle_tracks, alerts, night) -> None:
        h, w = frame.shape[:2]
        s = max(0.6, w / 960.0)
        for z in self.zones:  # tint only each zone's bounding box, not the whole frame
            pts = np.array(z.polygon, dtype=np.int32)
            x0, y0 = max(0, pts[:, 0].min()), max(0, pts[:, 1].min())
            x1_, y1_ = min(w, pts[:, 0].max() + 1), min(h, pts[:, 1].max() + 1)
            if x1_ <= x0 or y1_ <= y0:
                continue
            roi = frame[y0:y1_, x0:x1_]
            tinted = roi.copy()
            cv2.fillPoly(tinted, [pts - [x0, y0]], (30, 30, 150))
            cv2.addWeighted(tinted, 0.18, roi, 0.82, 0, roi)
        for z in self.zones:
            pts = np.array(z.polygon, dtype=np.int32)
            _dashed_poly(frame, pts, C_ZONE, max(1, int(2 * s)))
            x, y = pts[:, 0].min() + int(8 * s), pts[:, 1].min() + int(20 * s)
            _label(frame, z.name.upper(), (x, y), C_ZONE, 0.45 * s)
        for ln in self.lines:
            p1, p2 = tuple(map(int, ln.p1)), tuple(map(int, ln.p2))
            cv2.line(frame, p1, p2, C_LINE, max(2, int(3 * s)), cv2.LINE_AA)
            _direction_arrow(frame, ln, s)
            _label(frame, ln.name.upper(), (min(p1[0], p2[0]) + int(8 * s), min(p1[1], p2[1]) + int(58 * s)),
                   C_LINE, 0.45 * s)

        for t in person_tracks:
            if not t.misses:
                self._draw_track(frame, t, C_PERSON, s)
        for t in vehicle_tracks:
            if t.misses:
                continue
            plate = self._plate_cache.get(t.track_id)
            watch = plate is not None and plate_utils.match_watchlist(plate, _watch_cache()) is not None
            self._draw_track(frame, t, C_WATCH if watch else C_VEHICLE, s, plate, watch)

        # HUD
        bar_h = int(30 * s)
        cv2.rectangle(frame, (0, 0), (w, bar_h), (12, 14, 18), -1)
        mode = {"simulated": "SIMULATED", "upload": "REPLAY", "rtsp": "LIVE RTSP"}.get(self.source_kind, "LIVE")
        _text(frame, f"{self.name.upper()}  |  {mode}", (int(10 * s), int(20 * s)), (235, 235, 235), 0.5 * s)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        (tw, _), _ = cv2.getTextSize(ts, cv2.FONT_HERSHEY_SIMPLEX, 0.5 * s, 1)
        _text(frame, ts, (w - tw - int(40 * s), int(20 * s)), (200, 200, 200), 0.5 * s)
        if int(time.time() * 2) % 2 == 0:
            cv2.circle(frame, (w - int(20 * s), int(15 * s)), int(6 * s), (40, 40, 230), -1)
        stats = f"PERSONS {len(person_tracks)}   VEHICLES {len(vehicle_tracks)}"
        if night:
            stats += "   NIGHT / IR ENHANCED"
        cv2.rectangle(frame, (0, h - int(26 * s)), (w, h), (12, 14, 18), -1)
        _text(frame, stats, (int(10 * s), h - int(8 * s)), (180, 230, 200) if not night else (190, 140, 255), 0.45 * s)
        for i, a in enumerate(alerts[:2]):
            col = SEV_COLORS.get(a.severity, (0, 0, 255))
            y = h - int((40 + 26 * i) * s)
            msg = f"[{a.severity.upper()}] {a.message}"
            msg = msg if len(msg) < 90 else msg[:87] + "..."
            (mw, mh), _ = cv2.getTextSize(msg, cv2.FONT_HERSHEY_SIMPLEX, 0.5 * s, 1)
            cv2.rectangle(frame, (int(8 * s), y - mh - int(8 * s)), (int(16 * s) + mw, y + int(6 * s)), (12, 14, 18), -1)
            cv2.rectangle(frame, (int(8 * s), y - mh - int(8 * s)), (int(12 * s), y + int(6 * s)), col, -1)
            _text(frame, msg, (int(14 * s), y), col, 0.5 * s)

    def _draw_track(self, frame, t: Track, color, s, plate: Optional[str] = None, watch: bool = False) -> None:
        x1, y1, x2, y2 = t.bbox
        th = max(1, int(2 * s))
        _corner_box(frame, (x1, y1, x2, y2), color, th, watch)
        pts = [(int(p.x), int(p.y)) for p in list(t.history)[-30:]]
        for i in range(1, len(pts)):
            cv2.line(frame, pts[i - 1], pts[i], color, 1, cv2.LINE_AA)
        label = f"{'P' if t.label == 'person' else t.label[:3].upper()}-{t.track_id}"
        if plate:
            label += f"  {plate}"
        if watch:
            label += "  WATCHLIST"
        _label(frame, label, (x1, max(int(12 * s), y1 - int(6 * s))), color, 0.42 * s, filled=True)

    def build_payload(self, frame: np.ndarray, tracks: List[Track], alerts: List[Alert], extra: Optional[dict] = None,
                      quality: int = 72) -> dict:
        p = {
            "type": "frame", "camera_id": self.camera_id, "name": self.name, "source": self.source_kind,
            "frame_index": self.frame_index, "loop": self.loop_index,
            "people_count": len(self.tracker.tracks), "vehicle_count": len(self.vehicle_tracker.tracks),
            "night_mode": self.night_mode, "brightness": round(self.brightness, 1),
            "frame_w": int(frame.shape[1]), "frame_h": int(frame.shape[0]),
            "step_ms": round(self.last_step_ms, 1),
            "jpeg_b64": frame_to_jpeg_b64(frame, quality=quality),
            "tracks": [{"id": t.track_id, "label": t.label, "bbox": list(map(int, t.bbox)),
                        "plate": None if t.label == "person" else self._plate_cache.get(t.track_id),
                        "speed": round(t.speed_px_per_s(), 1)} for t in tracks if not t.misses][:40],
            "alerts": [alert_to_dict(a) for a in alerts],
        }
        if extra:
            p.update(extra)
        return p


# ---- helpers ------------------------------------------------------------
_watch = {"t": 0.0, "plates": []}


def _watch_cache() -> List[str]:
    if time.time() - _watch["t"] > 3:
        _watch["plates"], _watch["t"] = watchlist_plates(), time.time()
    return _watch["plates"]


def alert_to_dict(a: Alert) -> dict:
    return {"id": a.id, "alert_type": a.alert_type, "severity": a.severity, "message": a.message,
            "track_ids": a.track_ids, "timestamp": a.timestamp, "camera_id": a.camera_id,
            "snapshot_hash": a.snapshot_hash, "plate": a.plate, "created_at": time.time(), "status": "new"}


def _text(img, text, org, color, scale, thick=1):
    cv2.putText(img, text, org, cv2.FONT_HERSHEY_SIMPLEX, scale, color, thick, cv2.LINE_AA)


def _label(img, text, org, color, scale, filled=False):
    (tw, th), _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, scale, 1)
    x, y = org
    if filled:
        cv2.rectangle(img, (x, y - th - 6), (x + tw + 8, y + 3), color, -1)
        _text(img, text, (x + 4, y - 2), (15, 15, 15), scale)
    else:
        cv2.rectangle(img, (x - 3, y - th - 5), (x + tw + 5, y + 4), (12, 14, 18), -1)
        _text(img, text, (x + 1, y - 1), color, scale)


def _corner_box(img, box, color, th, emphasis=False):
    x1, y1, x2, y2 = box
    L = max(8, int(min(x2 - x1, y2 - y1) * 0.28))
    if emphasis:
        cv2.rectangle(img, (x1, y1), (x2, y2), color, 1)
    for (cx, cy, dx, dy) in ((x1, y1, 1, 1), (x2, y1, -1, 1), (x1, y2, 1, -1), (x2, y2, -1, -1)):
        cv2.line(img, (cx, cy), (cx + dx * L, cy), color, th + (1 if emphasis else 0), cv2.LINE_AA)
        cv2.line(img, (cx, cy), (cx, cy + dy * L), color, th + (1 if emphasis else 0), cv2.LINE_AA)


def _dashed_poly(img, pts, color, th, dash=14):
    n = len(pts)
    for i in range(n):
        p, q = pts[i].astype(float), pts[(i + 1) % n].astype(float)
        dist = float(np.linalg.norm(q - p))
        steps = max(1, int(dist // dash))
        for k in range(0, steps, 2):
            a = p + (q - p) * (k / steps)
            b = p + (q - p) * (min(steps, k + 1) / steps)
            cv2.line(img, tuple(a.astype(int)), tuple(b.astype(int)), color, th, cv2.LINE_AA)


def _direction_arrow(img, ln: BorderLine, s: float) -> None:
    """Draws an arrow across the line showing the UNAUTHORIZED direction."""
    (x1, y1), (x2, y2) = ln.p1, ln.p2
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    dx, dy = x2 - x1, y2 - y1
    norm = max(1e-6, (dx * dx + dy * dy) ** 0.5)
    nx, ny = -dy / norm, dx / norm          # points to side 'a' (cross >= 0)
    if ln.unauthorized_side == "a_to_b":
        nx, ny = -nx, -ny
    L = 34 * s
    start = (int(mx - nx * L), int(my - ny * L))
    end = (int(mx + nx * L), int(my + ny * L))
    cv2.arrowedLine(img, start, end, (60, 60, 255), max(2, int(2 * s)), cv2.LINE_AA, tipLength=0.35)


def frame_to_jpeg_b64(frame: np.ndarray, quality: int = 75, max_dim: int = 1280) -> str:
    """Caps the larger side before encoding: a 4K frame's base64 JPEG exceeds
    the 1 MB default WebSocket message limit and silently kills the stream.
    Detection already ran on the full-resolution frame."""
    h, w = frame.shape[:2]
    if max(h, w) > max_dim:
        scale = max_dim / max(h, w)
        frame = cv2.resize(frame, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    ok, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return base64.b64encode(buf.tobytes()).decode("ascii") if ok else ""
