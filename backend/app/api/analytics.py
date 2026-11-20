"""Analytics, threat level, zones, system status and the shift briefing."""

from __future__ import annotations

import html
import platform
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.config import APP_NAME, APP_VERSION, DETECTOR_BACKEND, TEAM_NAME
from app.core import crypto, storage
from app.core.anpr import anpr_service
from app.core.detector import yolo_available
from app.core.hub import hub
from app.core.streams import CAMERA_INDEX, SITE_CAMERAS, manager
from app.core.threat import compute_threat, site_threat
from app.core.zones import BorderLine, Zone

router = APIRouter()
STARTED_AT = time.time()


@router.get("/health")
def health():
    return {"status": "ok", "service": "ibvap-api", "version": APP_VERSION}


@router.get("/api/analytics/summary")
def summary(camera_id: Optional[str] = None, since_minutes: Optional[float] = None):
    since = time.time() - since_minutes * 60 if since_minutes else None
    return storage.fetch_summary(camera_id, since)


@router.get("/api/analytics/timeline")
def timeline(minutes: int = 30, bucket: int = 60, camera_id: Optional[str] = None):
    minutes = max(1, min(minutes, 24 * 60))
    bucket = max(10, min(bucket, 3600))
    return storage.fetch_timeline(minutes, bucket, camera_id)


def threat_snapshot() -> dict:
    per = compute_threat([c["id"] for c in SITE_CAMERAS])
    return {"cameras": per, "site": site_threat(per)}


@router.get("/api/analytics/threat")
def threat():
    return threat_snapshot()


@router.get("/api/analytics/occupancy/{camera_id}")
def occupancy(camera_id: str, minutes: int = 10):
    return storage.fetch_occupancy_series(camera_id, minutes)


# ---- zones --------------------------------------------------------------
class ZoneIn(BaseModel):
    name: str
    polygon: list[list[float]]
    zone_type: str = "restricted"


class LineIn(BaseModel):
    name: str
    p1: list[float]
    p2: list[float]
    unauthorized_side: str = "a_to_b"


class GeometryIn(BaseModel):
    zones: list[ZoneIn] = []
    lines: list[LineIn] = []
    replace: bool = False


@router.get("/api/zones/{camera_id}")
def get_zones(camera_id: str):
    return manager.session_for(camera_id).geometry_dict()


@router.post("/api/zones/{camera_id}")
def set_zones(camera_id: str, g: GeometryIn):
    s = manager.session_for(camera_id)
    for z in g.zones:
        if len(z.polygon) < 3:
            raise HTTPException(400, f"Zone {z.name!r} needs at least 3 points")
    for ln in g.lines:
        if ln.unauthorized_side not in ("a_to_b", "b_to_a"):
            raise HTTPException(400, "unauthorized_side must be a_to_b or b_to_a")
    new_zones = [Zone(i + 1, z.name, [tuple(p) for p in z.polygon], z.zone_type) for i, z in enumerate(g.zones)]
    new_lines = [BorderLine(i + 1, l.name, tuple(l.p1), tuple(l.p2), l.unauthorized_side) for i, l in enumerate(g.lines)]
    if g.replace:
        s.zones, s.lines = new_zones, new_lines
    else:
        s.zones = new_zones or s.zones
        s.lines = new_lines or s.lines
    storage.save_zones(camera_id, s.geometry_dict())
    return {"status": "updated", **s.geometry_dict()}


@router.delete("/api/zones/{camera_id}")
def reset_zones(camera_id: str):
    s = manager.session_for(camera_id)
    with storage._write_lock:
        conn = storage._wconn()
        conn.execute("DELETE FROM camera_zones WHERE camera_id = ?", (camera_id,))
        conn.commit()
    s._load_geometry()
    return {"status": "reset", **s.geometry_dict()}


# ---- system -------------------------------------------------------------
@router.get("/api/system/status")
def system_status():
    from app.core.anpr import _HAS_EASYOCR, _HAS_TESSERACT
    import app.core.detector as det
    yolo_loaded = det._shared_model is not None
    return {
        "product": APP_NAME, "version": APP_VERSION, "team": TEAM_NAME,
        "uptime_s": round(time.time() - STARTED_AT), "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}",
        "detector": {"configured": DETECTOR_BACKEND, "yolo_installed": yolo_available(),
                     "yolo_loaded": yolo_loaded,
                     "real_footage_backend": "YOLOv8n" if (yolo_loaded or (yolo_available() and DETECTOR_BACKEND != "hog"))
                     else "OpenCV HOG + MOG2"},
        "anpr": {**anpr_service.status(), "easyocr": _HAS_EASYOCR, "tesseract": _HAS_TESSERACT},
        "streams": [w.info() for w in manager.workers.values()],
        "event_bus": {"subscribers": hub.subscriber_count, "published": hub.published},
        "storage": storage.db_stats(),
        "signing_key": {"algorithm": "Ed25519", "fingerprint": crypto.key_fingerprint()},
    }


# ---- shift briefing -----------------------------------------------------
def _ts(t):
    return time.strftime("%d %b %H:%M:%S", time.localtime(t)) if t else "-"


@router.get("/api/reports/shift", response_class=HTMLResponse)
def shift_report(hours: float = 8.0):
    since = time.time() - hours * 3600
    s = storage.fetch_summary(since=since)
    v = storage.verify_all()
    th = threat_snapshot()
    top = [a for a in storage.fetch_alerts(400, since=since) if a["severity"] in ("critical", "high")][:15]
    wl = [w for w in storage.fetch_watchlist() if w["hits"]]
    e = html.escape
    cam_rows = "".join(
        f"<tr><td>{e(c['name'])}</td><td>{s['by_camera'].get(c['id'], 0)}</td>"
        f"<td><b class='lvl {th['cameras'][c['id']]['level'].lower()}'>{th['cameras'][c['id']]['level']}</b></td></tr>"
        for c in SITE_CAMERAS)
    type_rows = "".join(f"<tr><td>{e(k.replace('_', ' ').title())}</td><td>{n}</td></tr>"
                        for k, n in sorted(s["by_type"].items(), key=lambda kv: -kv[1])) or "<tr><td colspan=2>None</td></tr>"
    inc_rows = "".join(
        f"<tr><td>#{a['id']}</td><td>{_ts(a['created_at'])}</td><td>{e(CAMERA_INDEX.get(a['camera_id'], {}).get('name', a['camera_id']))}</td>"
        f"<td class='sev {a['severity']}'>{a['severity'].upper()}</td><td>{e(a['message'])}</td><td>{e(a['status'])}</td></tr>"
        for a in top) or "<tr><td colspan=6>No high or critical incidents in this window.</td></tr>"
    wl_rows = "".join(f"<tr><td><b>{e(w['plate'])}</b></td><td>{w['hits']}</td><td>{_ts(w['last_seen'])}</td>"
                      f"<td>{e(CAMERA_INDEX.get(w['last_camera'] or '', {}).get('name', w['last_camera'] or '-'))}</td></tr>"
                      for w in wl) or "<tr><td colspan=4>No watchlisted vehicle sighted.</td></tr>"
    ok = v["ok"]
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Shift Briefing - {APP_NAME}</title>
<style>
body{{font:13px/1.5 'Segoe UI',Arial,sans-serif;color:#101828;max-width:940px;margin:28px auto;padding:0 24px}}
h1{{font-size:22px;margin:0}} h2{{font-size:15px;margin:22px 0 6px;color:#0b3b66}}
header{{border-bottom:3px solid #0b3b66;padding-bottom:8px;display:flex;justify-content:space-between;align-items:flex-end}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:16px}}
.kpi{{border:1px solid #eaecf0;border-radius:8px;padding:10px}} .kpi b{{display:block;font-size:22px}} .kpi span{{color:#667085;font-size:11px;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse}} td,th{{padding:6px 8px;border-bottom:1px solid #eaecf0;text-align:left;vertical-align:top}}
th{{background:#f2f4f7;font-size:11px;text-transform:uppercase;color:#475467}}
.sev.critical{{color:#b42318;font-weight:700}} .sev.high{{color:#c4320a;font-weight:700}}
.lvl.critical{{color:#b42318}} .lvl.elevated{{color:#c4320a}} .lvl.guarded{{color:#b54708}} .lvl.low{{color:#137a4a}}
.verdict{{padding:10px 14px;border-radius:8px;font-weight:600;margin-top:14px;border:1px solid {'#137a4a' if ok else '#b42318'};color:{'#137a4a' if ok else '#b42318'}}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:18px}} footer{{margin-top:24px;color:#667085;font-size:11px}}
</style></head><body>
<header><div><h1>Shift Intelligence Briefing</h1><div>{APP_NAME} - last {hours:g} hours - site threat <b class="lvl {th['site']['level'].lower()}">{th['site']['level']}</b></div></div>
<div>{_ts(time.time())}</div></header>
<div class="kpis">
<div class="kpi"><b>{s['total_alerts']}</b><span>Alerts</span></div>
<div class="kpi"><b>{s['by_severity'].get('critical', 0)}</b><span>Critical</span></div>
<div class="kpi"><b>{s['open_alerts']}</b><span>Open</span></div>
<div class="kpi"><b>{s['unique_plates']}</b><span>Plates read</span></div>
<div class="kpi"><b>{s['watchlist_hits']}</b><span>Watchlist hits</span></div></div>
<div class="verdict">Evidence integrity: {'VERIFIED' if ok else 'FAILED'} - {v['chain']['records_checked']} chained records, {v['checkpoints']['total']} signed checkpoints (Ed25519 {crypto.key_fingerprint()})</div>
<div class="two"><div><h2>By camera</h2><table><tr><th>Camera</th><th>Alerts</th><th>Threat now</th></tr>{cam_rows}</table></div>
<div><h2>By type</h2><table><tr><th>Type</th><th>Count</th></tr>{type_rows}</table></div></div>
<h2>Watchlist sightings</h2><table><tr><th>Plate</th><th>Sightings</th><th>Last seen</th><th>Last camera</th></tr>{wl_rows}</table>
<h2>High and critical incidents</h2><table><tr><th>ID</th><th>Time</th><th>Camera</th><th>Severity</th><th>Description</th><th>Status</th></tr>{inc_rows}</table>
<footer>{APP_NAME} {APP_VERSION} - {TEAM_NAME}. Print, then Save as PDF, to file this briefing.</footer></body></html>"""
    return HTMLResponse(page)
