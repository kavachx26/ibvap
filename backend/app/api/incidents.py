"""Incidents: alert queue, workflow, evidence, reports."""

from __future__ import annotations

import hashlib
import html
import time
from typing import List, Optional

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from app.api.common import operator_of
from app.config import APP_NAME, APP_VERSION, SNAPSHOT_DIR, TEAM_NAME
from app.core import crypto, storage
from app.core.evidence import build_bundle, verify_bundle
from app.core.streams import CAMERA_INDEX

router = APIRouter()


class ActionIn(BaseModel):
    action: str
    note: Optional[str] = None
    assignee: Optional[str] = None


class BulkIn(BaseModel):
    ids: List[int]
    action: str
    note: Optional[str] = None


@router.get("/api/alerts")
def get_alerts(limit: int = 100, severity: Optional[str] = None, camera_id: Optional[str] = None,
               status: Optional[str] = None, alert_type: Optional[str] = None, q: Optional[str] = None,
               since_minutes: Optional[float] = None):
    since = time.time() - since_minutes * 60 if since_minutes else None
    return storage.fetch_alerts(min(limit, 1000), severity, camera_id, status, alert_type, since, q)


@router.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    alert = storage.fetch_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(404, f"No alert with id {alert_id}")
    integrity = storage.verify_integrity()
    audit = storage.fetch_audit_record(alert["audit_id"]) if alert.get("audit_id") else None
    cam = CAMERA_INDEX.get(alert["camera_id"], {})
    return {"alert": alert, "camera": cam, "actions": storage.fetch_alert_actions(alert_id), "audit_record": audit,
            "row_intact": alert_id not in integrity["tampered_alert_ids"]}


@router.post("/api/alerts/{alert_id}/acknowledge")
def ack_alert(alert_id: int, request: Request):
    if storage.record_alert_action(alert_id, "acknowledged", operator_of(request)) is None:
        raise HTTPException(404, f"No alert with id {alert_id}")
    return {"status": "acknowledged", "alert_id": alert_id}


@router.post("/api/alerts/{alert_id}/action")
def alert_action(alert_id: int, body: ActionIn, request: Request):
    try:
        res = storage.record_alert_action(alert_id, body.action, operator_of(request), body.note, body.assignee)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if res is None:
        raise HTTPException(404, f"No alert with id {alert_id}")
    return res


@router.post("/api/alerts/bulk")
def bulk_action(body: BulkIn, request: Request):
    op = operator_of(request)
    done = 0
    for i in body.ids[:500]:
        try:
            if storage.record_alert_action(i, body.action, op, body.note):
                done += 1
        except ValueError as e:
            raise HTTPException(400, str(e))
    return {"updated": done}


@router.get("/api/alerts/{alert_id}/snapshot")
def get_alert_snapshot(alert_id: int):
    """Serves the evidence frame after re-hashing it against the hash stored
    in the alert's chained audit record. A swapped file is refused (409)."""
    alert = storage.fetch_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(404, f"No alert with id {alert_id}")
    h = alert.get("snapshot_hash")
    if not h:
        raise HTTPException(404, "This alert has no evidence snapshot.")
    path = SNAPSHOT_DIR / f"{h}.jpg"
    if not path.exists():
        raise HTTPException(410, "Snapshot file is missing from disk.")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != h:
        raise HTTPException(409, f"TAMPER DETECTED: snapshot no longer matches its chained hash "
                                 f"(expected {h[:12]}..., found {actual[:12]}...).")
    return FileResponse(path, media_type="image/jpeg", headers={"X-Evidence-SHA256": h})


@router.get("/api/alerts/{alert_id}/evidence")
def get_evidence_bundle(alert_id: int, request: Request):
    data = build_bundle(alert_id, exported_by=operator_of(request))
    if data is None:
        raise HTTPException(404, f"No alert with id {alert_id}")
    storage.record_alert_action(alert_id, "note", operator_of(request), "Signed evidence bundle exported")
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="IBVAP_evidence_alert_{alert_id}.zip"'})


@router.post("/api/evidence/verify")
async def verify_evidence(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "Bundle too large")
    return verify_bundle(data)


def _fmt_ts(ts: Optional[float]) -> str:
    return time.strftime("%d %b %Y, %H:%M:%S", time.localtime(ts)) if ts else "-"


@router.get("/api/alerts/{alert_id}/report", response_class=HTMLResponse)
def get_alert_report(alert_id: int, api_key: str = Query(...)):
    alert = storage.fetch_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(404, f"No alert with id {alert_id}")
    v = storage.verify_all()
    row_ok = alert_id not in v["integrity"]["tampered_alert_ids"]
    ok = v["chain"]["chain_intact"] and v["checkpoints"]["ok"] and row_ok
    col = "#137a4a" if ok else "#b42318"
    verdict = ("VERIFIED. This record matches its hash-chained snapshot and the chain matches its signed checkpoints."
               if ok else "FAILED. This record or the audit chain failed verification. Treat as evidence of tampering.")
    e = html.escape
    cam = CAMERA_INDEX.get(alert["camera_id"], {})
    actions = storage.fetch_alert_actions(alert_id)
    rows = "".join(f"<tr><td>{_fmt_ts(a['created_at'])}</td><td>{e(a['operator'])}</td><td>{e(a['action'])}</td>"
                   f"<td>{e(a['note'] or '')}</td></tr>" for a in actions) or \
        "<tr><td colspan=4 class=muted>No operator actions recorded yet.</td></tr>"
    snap = (f'<img src="/api/alerts/{alert_id}/snapshot?api_key={e(api_key)}" alt="Evidence snapshot">'
            if alert.get("snapshot_hash") else '<p class="muted">No evidence frame was captured for this alert.</p>')
    sev_col = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467"}.get(alert["severity"], "#475467")
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Incident report #{alert_id} - {APP_NAME}</title>
<style>
 body{{font:14px/1.5 'Segoe UI',Arial,sans-serif;color:#101828;max-width:860px;margin:32px auto;padding:0 24px}}
 header{{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:3px solid #0b3b66;padding-bottom:10px}}
 h1{{font-size:22px;margin:0}} .sub{{color:#475467;font-size:12px}}
 .badge{{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-weight:600;font-size:12px;background:{sev_col}}}
 table{{width:100%;border-collapse:collapse;margin:14px 0}} td,th{{padding:7px 10px;border-bottom:1px solid #eaecf0;text-align:left;vertical-align:top}}
 th{{background:#f2f4f7;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#475467}}
 td.k{{color:#475467;width:180px;font-weight:600}} .mono{{font-family:Consolas,monospace;font-size:11px;word-break:break-all}}
 img{{max-width:100%;border:1px solid #d0d5dd;border-radius:8px}} .muted{{color:#667085;font-style:italic}}
 .verdict{{margin:18px 0;padding:12px 16px;border-radius:8px;border:1px solid {col};background:{col}12;color:{col};font-weight:600}}
 footer{{margin-top:28px;font-size:11px;color:#667085;border-top:1px solid #eaecf0;padding-top:8px}}
 @media print{{body{{margin:0}} .noprint{{display:none}}}}
</style></head><body>
<header><div><h1>Incident Report #{alert_id}</h1><div class="sub">{APP_NAME} - Intelligent Border Video Analytics Platform</div></div>
<div class="sub">Generated {_fmt_ts(time.time())}</div></header>
<div class="verdict">Integrity: {verdict}</div>
<table>
<tr><td class="k">Type</td><td>{e(alert['alert_type'].replace('_', ' ').title())}</td></tr>
<tr><td class="k">Severity</td><td><span class="badge">{e(alert['severity'].upper())}</span></td></tr>
<tr><td class="k">Description</td><td>{e(alert['message'])}</td></tr>
<tr><td class="k">Camera</td><td>{e(cam.get('name', alert['camera_id']))} <span class="sub">({e(alert['camera_id'])}{', ' + e(cam['post']) if cam.get('post') else ''})</span></td></tr>
<tr><td class="k">Detected at</td><td>{_fmt_ts(alert['created_at'])} <span class="sub">(stream time t+{alert['timestamp']:.1f}s)</span></td></tr>
<tr><td class="k">Track ID(s)</td><td>{e(alert['track_ids'])}</td></tr>
{f"<tr><td class='k'>Vehicle plate</td><td><b>{e(alert['plate'])}</b></td></tr>" if alert.get('plate') else ''}
<tr><td class="k">Status</td><td>{e(alert['status'].replace('_', ' ').title())}{' (assigned to ' + e(alert['assignee']) + ')' if alert.get('assignee') else ''}</td></tr>
<tr><td class="k">Evidence SHA-256</td><td class="mono">{e(alert.get('snapshot_hash') or '(none)')}</td></tr>
<tr><td class="k">Audit record</td><td class="mono">#{alert.get('audit_id')}</td></tr>
<tr><td class="k">Signing key</td><td class="mono">Ed25519 {crypto.key_fingerprint()}</td></tr>
</table>
<h3>Evidence frame</h3>{snap}
<h3>Chain of custody</h3>
<table><tr><th>Time</th><th>Operator</th><th>Action</th><th>Note</th></tr>{rows}</table>
<footer>{APP_NAME} {APP_VERSION} - {TEAM_NAME}. Every row above is hash-chained in the audit log.
Use the browser's Print, then Save as PDF, to file this report. <span class="noprint">Download the signed evidence bundle from the dashboard for offline verification.</span></footer>
</body></html>"""
    return HTMLResponse(page)
