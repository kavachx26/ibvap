"""
simulator.py
------------
Deterministic multi-camera scenarios for demos and tests.

A judge should be able to run one command and watch every alert type fire
on schedule, without a restricted border-CCTV dataset and without the demo
depending on a live camera. Each Scenario scripts a cast of actors (people
and vehicles) frame by frame. Their positions become Detection objects that
feed the SAME tracker, behaviour analytics, ANPR/watchlist logic, evidence
capture and audit chain used for real footage. Only the detector is replaced
by a script, and the UI labels these feeds "SIMULATED".

Four scenarios, one per camera of the demo site:
  fence     North fence: loitering, group, unauthorized crossing, sprinter, night
  checkpost ANPR lane: inspections, a vehicle parked in a no-parking zone,
            a wrong-way vehicle through the barrier, watchlisted plates
  river     Riverine crossing at night: a group wading across the bank line
  road      Perimeter road: vehicle convoy, a vehicle stopping in a restricted
            siding, an erratic runner, a reverse-direction vehicle
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import cv2
import numpy as np

from app.core.detector import Detection
from app.core.zones import BorderLine, Zone

# Plates that rotate through every camera, so the same vehicle is seen at
# several posts and its cross-camera trajectory can be reconstructed.
NORMAL_PLATES = [
    "MH12AB1234", "DL1CN4521", "KA05MN7788", "UP32HT4410", "RJ14CV9012", "PB10GH3345",
    "TN09BX6621", "WB06F8899", "GJ01RT5567", "HR26DK8031", "BR01PQ2290", "OD02ZX4417",
]


@dataclass
class Actor:
    actor_id: int
    path_fn: Callable[[int], Tuple[float, float]]
    label: str = "person"
    active_range: Tuple[int, int] = (0, 10_000)
    color: Tuple[int, int, int] = (90, 200, 255)
    plate_slot: Optional[int] = None
    facing: int = 1  # +1 drives right, -1 drives left

    def position_at(self, frame_index: int):
        if frame_index < self.active_range[0] or frame_index > self.active_range[1]:
            return None
        return self.path_fn(frame_index - self.active_range[0])


@dataclass
class Scenario:
    key: str
    loop_frames: int
    actors: List[Actor]
    zones: List[Zone]
    lines: List[BorderLine]
    night_ranges: List[Tuple[int, int]] = field(default_factory=list)
    # (loop % 3, slot) -> watchlisted plate shown in that loop
    watch_rules: Dict[Tuple[int, int], str] = field(default_factory=dict)
    plate_seed: int = 0
    # DBSCAN radius for vehicle convoys. Vehicles queueing in separate lanes
    # at a check post are not a convoy, so that scenario uses a tighter radius.
    vehicle_group_eps: float = 200.0
    background: Optional[np.ndarray] = None

    def is_night(self, f: int) -> bool:
        return any(a <= f <= b for a, b in self.night_ranges)

    def plate_for(self, slot: int, loop: int) -> str:
        rule = self.watch_rules.get((loop % 3, slot))
        if rule:
            return rule
        return NORMAL_PLATES[(slot * 5 + loop * 2 + self.plate_seed) % len(NORMAL_PLATES)]


# ---- path helpers -------------------------------------------------------
def _linear(x0, y0, x1, y1, speed):
    dist = math.hypot(x1 - x0, y1 - y0)
    steps = max(1.0, dist / speed)

    def fn(f):
        p = min(1.0, f / steps)
        return (x0 + (x1 - x0) * p, y0 + (y1 - y0) * p)
    return fn


def _drive_with_stop(x0, x1, y, speed, stop_x, stop_frames):
    """Drives along y from x0 to x1, pausing at stop_x for stop_frames."""
    d1 = abs(stop_x - x0) / speed
    direction = 1 if x1 >= x0 else -1

    def fn(f):
        if f <= d1:
            return (x0 + direction * speed * f, y)
        if f <= d1 + stop_frames:
            return (stop_x, y + 0.4 * math.sin(f * 0.3))
        return (stop_x + direction * speed * (f - d1 - stop_frames), y)
    return fn


def _hold(x, y, jitter=4.0):
    return lambda f: (x + jitter * math.sin(f * 0.15), y + jitter * 0.7 * math.cos(f * 0.2))


# ---- scenario builders --------------------------------------------------
def _fence(w: int, h: int) -> Scenario:
    fx = w * 0.55

    def sprinter(f):
        return ((w * 0.08 + 55 * f) % w, (h * 0.18 + 40 * math.sin(f * 0.5) + f * 4.5) % (h * 0.7))

    actors = [
        Actor(1, _hold(fx + 70, h * 0.36), active_range=(0, 330), color=(80, 170, 255)),
        Actor(2, lambda f: (40 + (2.0 * f) % (fx - 120), h * 0.16), active_range=(0, 410), color=(200, 200, 120)),
        Actor(3, _linear(w * 0.30, h * 0.70, fx - 70, h * 0.52, 3.0), active_range=(40, 330), color=(120, 220, 160)),
        Actor(4, _linear(w * 0.24, h * 0.42, fx - 110, h * 0.47, 3.0), active_range=(40, 330), color=(140, 160, 255)),
        Actor(5, _linear(w * 0.18, h * 0.60, fx - 120, h * 0.58, 3.0), active_range=(40, 330), color=(255, 160, 140)),
        Actor(6, lambda f: (min(30 + 4.5 * f, w - 30), h * 0.70), active_range=(150, 400), color=(60, 120, 255)),
        Actor(7, sprinter, active_range=(205, 245), color=(255, 120, 255)),
        Actor(8, lambda f: ((20 + 3.4 * f) % (w + 160) - 80, h * 0.89), "vehicle", (0, 400),
              color=(60, 70, 170), plate_slot=0),
    ]
    zones = [Zone(1, "Restricted Buffer Strip", [(fx, 0), (w, 0), (w, h * 0.8), (fx, h * 0.8)])]
    lines = [BorderLine(1, "Border Fence Line", (fx, 0), (fx, h * 0.8), unauthorized_side="a_to_b")]
    return Scenario("fence", 420, actors, zones, lines, night_ranges=[(280, 360)],
                    watch_rules={(1, 0): "WB74AK2231"}, plate_seed=1)


def _checkpost(w: int, h: int) -> Scenario:
    bx = w * 0.62
    lane1, lane2 = h * 0.47, h * 0.70
    actors = [
        Actor(1, _drive_with_stop(-60, w + 80, lane1, 4.0, bx - 70, 36), "vehicle", (0, 330),
              color=(40, 40, 40), plate_slot=0),
        Actor(2, lambda f: (-60 + 4.6 * f, lane2), "vehicle", (55, 330), color=(170, 110, 40), plate_slot=1),
        Actor(3, _drive_with_stop(-60, w + 80, lane1, 4.2, w * 0.80, 150), "vehicle", (150, 419),
              color=(200, 200, 200), plate_slot=2),
        Actor(4, lambda f: (w + 60 - 5.2 * f, lane2), "vehicle", (275, 419), color=(40, 40, 160),
              plate_slot=3, facing=-1),
        Actor(5, _hold(w * 0.55, h * 0.27, 2.0), active_range=(0, 419), color=(60, 140, 60)),
        Actor(6, lambda f: (w * 0.15 + 1.8 * f, h * 0.88), active_range=(30, 300), color=(200, 180, 120)),
    ]
    zones = [Zone(1, "No-Parking Zone", [(w * 0.70, h * 0.36), (w * 0.97, h * 0.36), (w * 0.97, h * 0.80),
                                          (w * 0.70, h * 0.80)])]
    lines = [BorderLine(1, "Barrier Line", (bx, h * 0.33), (bx, h * 0.83), unauthorized_side="b_to_a")]
    return Scenario("checkpost", 420, actors, zones, lines,
                    watch_rules={(0, 0): "WB74AK2231", (2, 1): "AS01BC9087"}, plate_seed=4,
                    vehicle_group_eps=90.0)


def _river(w: int, h: int) -> Scenario:
    by = h * 0.50
    actors = [
        Actor(1, _linear(w * 0.40, h * 0.92, w * 0.38, h * 0.20, 1.6), active_range=(70, 400), color=(120, 220, 160)),
        Actor(2, _linear(w * 0.45, h * 0.94, w * 0.44, h * 0.22, 1.6), active_range=(70, 400), color=(140, 160, 255)),
        Actor(3, _linear(w * 0.50, h * 0.92, w * 0.50, h * 0.21, 1.6), active_range=(70, 400), color=(255, 160, 140)),
        Actor(4, _hold(w * 0.78, h * 0.44, 3.0), active_range=(180, 360), color=(80, 170, 255)),
        Actor(5, lambda f: (30 + (1.5 * f) % (w - 60), h * 0.14), active_range=(0, 419), color=(60, 140, 60)),
    ]
    zones = [Zone(1, "Bank Buffer Strip", [(0, h * 0.36), (w, h * 0.36), (w, by), (0, by)])]
    lines = [BorderLine(1, "River Bank Line", (0, by), (w, by), unauthorized_side="a_to_b")]
    return Scenario("river", 420, actors, zones, lines, night_ranges=[(40, 400)], plate_seed=7)


def _road(w: int, h: int) -> Scenario:
    lane = h * 0.62
    actors = [
        Actor(1, lambda f: (-60 + 4.0 * f, lane), "vehicle", (20, 300), color=(60, 90, 60), plate_slot=0),
        Actor(2, lambda f: (-60 + 4.0 * f, lane), "vehicle", (57, 337), color=(70, 100, 70), plate_slot=1),
        Actor(3, lambda f: (w * 0.2 + 3.0 * min(f, 120), lane - (min(max(f - 120, 0), 50) * 2.6)),
              "vehicle", (140, 419), color=(150, 150, 150), plate_slot=2),
        Actor(4, lambda f: (w + 60 - 6.0 * f, h * 0.80), "vehicle", (300, 419), color=(30, 30, 140),
              plate_slot=3, facing=-1),
        Actor(5, lambda f: ((w * 0.1 + 55 * f) % w, h * 0.30 + 30 * math.sin(f * 0.6)),
              active_range=(230, 262), color=(255, 120, 255)),
    ]
    zones = [Zone(1, "Restricted Siding", [(w * 0.50, h * 0.18), (w * 0.95, h * 0.18), (w * 0.95, h * 0.46),
                                            (w * 0.50, h * 0.46)])]
    lines = [BorderLine(1, "Sector 7 Boundary", (w * 0.86, h * 0.50), (w * 0.86, h * 0.95), unauthorized_side="b_to_a")]
    return Scenario("road", 420, actors, zones, lines, night_ranges=[(330, 400)],
                    watch_rules={(2, 0): "WB74AK2231", (0, 1): "AS01BC9087"}, plate_seed=9)


_BUILDERS = {"fence": _fence, "checkpost": _checkpost, "river": _river, "road": _road}


def build_scenario(key: str, w: int = 960, h: int = 540) -> Scenario:
    sc = _BUILDERS.get(key, _fence)(w, h)
    sc.background = render_background(sc.key, w, h)
    return sc


# ---- detections ---------------------------------------------------------
PERSON_W, PERSON_H = 26, 46
VEH_W, VEH_H = 112, 54


def frame_detections(actors: List[Actor], frame_index: int) -> List[Tuple[Detection, Actor]]:
    out = []
    for a in actors:
        pos = a.position_at(frame_index)
        if pos is None:
            continue
        x, y = pos
        if a.label == "vehicle":
            d = Detection(int(x - VEH_W / 2), int(y - VEH_H / 2), int(x + VEH_W / 2), int(y + VEH_H / 2), 0.93, "vehicle")
        else:
            d = Detection(int(x - PERSON_W / 2), int(y - PERSON_H), int(x + PERSON_W / 2), int(y), 0.95, "person")
        out.append((d, a))
    return out


# ---- rendering ----------------------------------------------------------
def _noise_texture(h, w, base, amp, seed):
    rng = np.random.default_rng(seed)
    n = rng.integers(-amp, amp + 1, size=(h // 4 + 1, w // 4 + 1, 1), dtype=np.int16)
    n = cv2.resize(n.astype(np.float32), (w, h), interpolation=cv2.INTER_LINEAR)[..., None]
    img = np.clip(np.array(base, dtype=np.float32)[None, None, :] + n, 0, 255).astype(np.uint8)
    return img


def render_background(key: str, w: int, h: int) -> np.ndarray:
    if key == "checkpost":
        img = _noise_texture(h, w, (70, 88, 84), 10, 2)
        cv2.rectangle(img, (0, int(h * 0.34)), (w, int(h * 0.84)), (58, 60, 62), -1)
        for x in range(0, w, 70):
            cv2.line(img, (x, int(h * 0.585)), (x + 38, int(h * 0.585)), (200, 200, 200), 2)
        cv2.line(img, (0, int(h * 0.34)), (w, int(h * 0.34)), (180, 180, 180), 2)
        cv2.line(img, (0, int(h * 0.84)), (w, int(h * 0.84)), (180, 180, 180), 2)
        bx = int(w * 0.62)
        cv2.rectangle(img, (bx - 120, int(h * 0.12)), (bx - 30, int(h * 0.30)), (70, 110, 150), -1)
        cv2.rectangle(img, (bx - 120, int(h * 0.12)), (bx - 30, int(h * 0.30)), (40, 60, 90), 2)
        cv2.putText(img, "CHECK POST", (bx - 116, int(h * 0.11)), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (220, 220, 220), 1, cv2.LINE_AA)
        for k in range(0, int(h * 0.50), 18):
            c = (40, 40, 210) if (k // 18) % 2 == 0 else (235, 235, 235)
            cv2.line(img, (bx, int(h * 0.33) + k), (bx, int(h * 0.33) + k + 18), c, 5)
        return img
    if key == "river":
        img = _noise_texture(h, w, (52, 82, 64), 12, 3)
        cv2.rectangle(img, (0, int(h * 0.60)), (w, h), (120, 82, 40), -1)
        river = _noise_texture(int(h * 0.40) + 1, w, (130, 92, 48), 14, 5)
        img[int(h * 0.60):, :] = river[: h - int(h * 0.60)]
        for x in range(0, w, 46):
            cv2.ellipse(img, (x + 18, int(h * 0.72) + (x % 3) * 22), (16, 3), 0, 0, 360, (160, 120, 80), 1)
        cv2.rectangle(img, (0, int(h * 0.50)), (w, int(h * 0.60)), (70, 104, 120), -1)
        for x in range(10, w, 60):
            cv2.circle(img, (x, int(h * 0.30) - (x % 5) * 6), 14, (34, 60, 40), -1)
        return img
    if key == "road":
        img = _noise_texture(h, w, (60, 92, 80), 11, 4)
        cv2.rectangle(img, (0, int(h * 0.52)), (w, int(h * 0.90)), (62, 62, 64), -1)
        for x in range(0, w, 80):
            cv2.line(img, (x, int(h * 0.71)), (x + 44, int(h * 0.71)), (0, 200, 230), 2)
        cv2.rectangle(img, (int(w * 0.50), int(h * 0.18)), (int(w * 0.95), int(h * 0.46)), (84, 88, 90), -1)
        cv2.line(img, (int(w * 0.86), int(h * 0.50)), (int(w * 0.86), int(h * 0.95)), (40, 40, 200), 1)
        return img
    # fence (default)
    img = _noise_texture(h, w, (58, 86, 76), 12, 1)
    cv2.rectangle(img, (0, int(h * 0.82)), (w, int(h * 0.96)), (88, 96, 104), -1)
    fx = int(w * 0.55)
    for y in range(0, int(h * 0.8), 26):
        cv2.line(img, (fx - 4, y), (fx + 4, y + 13), (150, 150, 150), 1)
        cv2.line(img, (fx + 4, y + 13), (fx - 4, y + 26), (150, 150, 150), 1)
    for y in range(0, int(h * 0.8), 52):
        cv2.rectangle(img, (fx - 3, y), (fx + 3, y + 8), (110, 110, 110), -1)
    for x in range(fx + 40, w, 70):
        cv2.circle(img, (x, int(h * 0.08) + (x % 7) * 3), 18, (40, 64, 46), -1)
    return img


def draw_actor(canvas: np.ndarray, a: Actor, pos, plate: Optional[str], night: bool) -> None:
    x, y = int(pos[0]), int(pos[1])
    if a.label == "vehicle":
        hw, hh = VEH_W // 2, VEH_H // 2
        body = a.color
        cv2.rectangle(canvas, (x - hw, y - hh + 8), (x + hw, y + hh - 6), body, -1)
        cv2.rectangle(canvas, (x - hw + 22, y - hh), (x + hw - 26, y - hh + 14), tuple(int(c * 0.8) for c in body), -1)
        cv2.rectangle(canvas, (x - hw + 26, y - hh + 2), (x + hw - 30, y - hh + 12), (150, 110, 70), -1)
        cv2.rectangle(canvas, (x - hw, y - hh + 8), (x + hw, y + hh - 6), (20, 20, 20), 1)
        for wx in (x - hw + 22, x + hw - 22):
            cv2.circle(canvas, (wx, y + hh - 6), 8, (15, 15, 15), -1)
            cv2.circle(canvas, (wx, y + hh - 6), 3, (110, 110, 110), -1)
        front = x + hw - 3 if a.facing > 0 else x - hw + 3
        light = (120, 240, 255) if night else (170, 220, 230)
        cv2.circle(canvas, (front, y - 2), 4, light, -1)
        if night:
            cv2.ellipse(canvas, (front + 40 * a.facing, y), (40, 14), 0, 0, 360, (60, 110, 120), -1)
        if plate:
            px1, py1 = x - 34, y + 4
            cv2.rectangle(canvas, (px1, py1), (px1 + 68, py1 + 15), (245, 245, 245), -1)
            cv2.rectangle(canvas, (px1, py1), (px1 + 68, py1 + 15), (30, 30, 30), 1)
            cv2.putText(canvas, plate, (px1 + 3, py1 + 11), cv2.FONT_HERSHEY_SIMPLEX, 0.30, (10, 10, 10), 1, cv2.LINE_AA)
    else:
        c = a.color
        cv2.circle(canvas, (x, y - PERSON_H + 7), 6, (150, 180, 210), -1)
        cv2.rectangle(canvas, (x - 7, y - PERSON_H + 14), (x + 7, y - 18), c, -1)
        cv2.line(canvas, (x - 3, y - 18), (x - 6, y - 1), (40, 40, 40), 3)
        cv2.line(canvas, (x + 3, y - 18), (x + 6, y - 1), (40, 40, 40), 3)


def apply_night(canvas: np.ndarray, frame_index: int) -> np.ndarray:
    """IR-camera look: dark, green-tinted, a little sensor noise."""
    dark = cv2.convertScaleAbs(canvas, alpha=0.42, beta=0)
    g = cv2.cvtColor(dark, cv2.COLOR_BGR2GRAY)
    tint = cv2.merge([g // 2, np.clip(g.astype(np.int16) * 13 // 10, 0, 255).astype(np.uint8), g // 2])
    rng = np.random.default_rng(frame_index)
    noise = rng.integers(0, 9, size=g.shape, dtype=np.uint8)
    tint[:, :, 1] = cv2.add(tint[:, :, 1], noise)
    return tint
