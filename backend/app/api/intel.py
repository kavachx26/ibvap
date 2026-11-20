"""Vehicle intelligence: ANPR sightings, cross-camera trajectories, watchlist,
and the detection event log."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.common import operator_of
from app.core import plates as plate_utils
from app.core import storage
from app.core.streams import CAMERA_INDEX, SITE_CAMERAS

router = APIRouter()


class WatchIn(BaseModel):
    plate: str = Field(..., min_length=4, max_length=20)  # raw input may contain spaces / dashes
    reason: str = Field(..., min_length=3, max_length=200)
    priority: str = "high"


@router.get("/api/events")
def get_events(limit: int = 100, event_type: Optional[str] = None, camera_id: Optional[str] = None):
    return storage.fetch_events(min(limit, 1000), event_type, camera_id)


@router.get("/api/intel/plates")
def plates(q: Optional[str] = None, limit: int = 200):
    rows = storage.fetch_plates(limit, q)
    for r in rows:
        r["format_valid"] = bool(r["format_valid"])
    return rows


@router.get("/api/intel/plates/{plate}/trajectory")
def trajectory(plate: str):
    plate = plate_utils.clean(plate)
    sightings = storage.fetch_trajectory(plate)
    if not sightings:
        raise HTTPException(404, f"No sightings for {plate}")
    for s in sightings:
        cam = CAMERA_INDEX.get(s["camera_id"], {})
        s["camera_name"] = cam.get("name", s["camera_id"])
        s["map_x"], s["map_y"] = cam.get("map_x"), cam.get("map_y")
    legs = []
    for a, b in zip(sightings, sightings[1:]):
        if a["camera_id"] == b["camera_id"]:
            continue
        legs.append({"from": a["camera_id"], "to": b["camera_id"], "from_name": a["camera_name"],
                     "to_name": b["camera_name"], "elapsed_s": round(b["created_at"] - a["created_at"], 1)})
    wl = storage.watchlist_entry(plate)
    return {"plate": plate, "format_valid": plate_utils.is_valid_format(plate), "watchlist": wl,
            "total_sightings": len(sightings), "cameras": sorted({s["camera_id"] for s in sightings}),
            "first_seen": sightings[0]["created_at"], "last_seen": sightings[-1]["created_at"],
            "sightings": sightings, "legs": legs}


@router.get("/api/intel/site-map")
def site_map():
    return {"cameras": SITE_CAMERAS}


@router.get("/api/intel/watchlist")
def get_watchlist():
    return storage.fetch_watchlist()


@router.post("/api/intel/watchlist")
def add_watchlist(body: WatchIn, request: Request):
    plate = plate_utils.clean(body.plate)
    if len(plate) < 4:
        raise HTTPException(400, "Plate too short after cleaning")
    if body.priority not in ("high", "critical"):
        raise HTTPException(400, "priority must be 'high' or 'critical'")
    res = storage.watchlist_add(plate, body.reason.strip(), body.priority, operator_of(request))
    res["format_valid"] = plate_utils.is_valid_format(plate)
    return res


@router.delete("/api/intel/watchlist/{plate}")
def delete_watchlist(plate: str, request: Request):
    if not storage.watchlist_remove(plate_utils.clean(plate), operator_of(request)):
        raise HTTPException(404, f"{plate} is not on the watchlist")
    return {"status": "removed", "plate": plate_utils.clean(plate)}


@router.get("/api/intel/match")
def test_match(plate: str):
    """Shows how an OCR read would be matched against the watchlist."""
    m = plate_utils.match_watchlist(plate, storage.watchlist_plates())
    return {"read": plate_utils.clean(plate), "repaired": plate_utils.repair(plate),
            "format_valid": plate_utils.is_valid_format(plate_utils.repair(plate)),
            "match": {"plate": m[0], "type": m[1]} if m else None}
