"""
threat.py
---------
Per-camera threat level: one number an operator can read at a glance
instead of scanning a list of alerts.

raw   = sum over recent open alerts of weight(severity) * exp(-age / tau)
score = 100 * (1 - exp(-raw / 70))

Recent alerts count most and fade over a few minutes (tau = 75 s). Alerts an
operator has resolved or marked false positive stop counting, so clearing
the queue visibly lowers the level. Capped at 100.
"""

from __future__ import annotations

import math
import time
from typing import Dict, List, Optional

from app.core.storage import recent_alerts_for_threat

WEIGHTS = {"low": 2.0, "medium": 6.0, "high": 15.0, "critical": 40.0}
TAU_S = 75.0
# Raw weight is squashed with 100 * (1 - exp(-raw / SATURATION)): one critical
# alert reads ELEVATED (~44), a burst of critical alerts reaches CRITICAL, and
# a steady trickle of low-severity events never pins the gauge at 100.
SATURATION = 70.0
LEVELS = [(70, "CRITICAL"), (40, "ELEVATED"), (20, "GUARDED"), (0, "LOW")]
CLOSED = {"resolved", "false_positive"}


def level_for(score: float) -> str:
    for floor, name in LEVELS:
        if score >= floor:
            return name
    return "LOW"


def compute_threat(camera_ids: Optional[List[str]] = None, now: Optional[float] = None) -> Dict[str, dict]:
    now = now or time.time()
    scores: Dict[str, float] = {c: 0.0 for c in (camera_ids or [])}
    counts: Dict[str, int] = {c: 0 for c in (camera_ids or [])}
    for a in recent_alerts_for_threat(window_s=TAU_S * 6):
        if a["status"] in CLOSED:
            continue
        age = max(0.0, now - a["created_at"])
        cam = a["camera_id"]
        scores[cam] = scores.get(cam, 0.0) + WEIGHTS.get(a["severity"], 5.0) * math.exp(-age / TAU_S)
        counts[cam] = counts.get(cam, 0) + 1
    out = {}
    for cam, raw in scores.items():
        s = 100.0 * (1.0 - math.exp(-raw / SATURATION))
        out[cam] = {"camera_id": cam, "score": round(s, 1), "level": level_for(s), "recent_open_alerts": counts[cam]}
    return out


def site_threat(per_camera: Dict[str, dict]) -> dict:
    """Site level = the worst camera, nudged up when several cameras are hot
    at once (a coordinated event across sectors matters more than one)."""
    if not per_camera:
        return {"score": 0.0, "level": "LOW", "hot_cameras": 0}
    vals = sorted((v["score"] for v in per_camera.values()), reverse=True)
    hot = sum(1 for v in vals if v >= 40)
    s = min(100.0, vals[0] + 0.15 * sum(vals[1:3]))
    return {"score": round(s, 1), "level": level_for(s), "hot_cameras": hot}
