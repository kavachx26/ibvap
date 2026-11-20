"""End-to-end API tests: auth, live streams, incident workflow, signed
evidence, the three tamper attacks, watchlist/ANPR, zones and reports."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.config import API_KEY
from app.main import app

H = {"X-API-Key": API_KEY, "X-Operator": "Insp. Test"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def read_frames(client, stream, n):
    frames = []
    with client.websocket_connect(f"/api/ws/stream/{stream}?api_key={API_KEY}") as ws:
        for _ in range(n):
            msg = json.loads(ws.receive_text())
            assert msg["type"] == "frame", msg
            frames.append(msg)
    return frames


def test_health_is_open_and_api_needs_key(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/alerts", headers=H).status_code == 200


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "IBVAP" in r.text


def test_checkpost_stream_reads_watchlisted_plate(client):
    frames = read_frames(client, "cam-02", 45)  # plate is read once the car is fully in view (~30 frames)
    f = frames[-1]
    assert f["jpeg_b64"] and f["camera_id"] == "cam-02" and f["source"] == "simulated"
    assert any(t["plate"] for t in f["tracks"] if t["label"] == "vehicle")
    alerts = client.get("/api/alerts?alert_type=watchlist_match", headers=H).json()
    assert alerts, "loop 0 of the check-post scenario shows a watchlisted plate"
    assert alerts[0]["plate"] == "WB74AK2231" and alerts[0]["severity"] == "critical"
    assert alerts[0]["snapshot_hash"]
    traj = client.get("/api/intel/plates/WB74AK2231/trajectory", headers=H).json()
    assert traj["total_sightings"] >= 1 and traj["watchlist"]["plate"] == "WB74AK2231"


def test_incident_workflow_and_custody(client):
    alert = client.get("/api/alerts?limit=1", headers=H).json()[0]
    aid = alert["id"]
    for action in ("acknowledged", "investigating", "escalated"):
        r = client.post(f"/api/alerts/{aid}/action", json={"action": action, "note": f"step {action}"}, headers=H)
        assert r.status_code == 200
    detail = client.get(f"/api/alerts/{aid}", headers=H).json()
    assert detail["alert"]["status"] == "escalated"
    assert [a["action"] for a in detail["actions"]] == ["acknowledged", "investigating", "escalated"]
    assert all(a["operator"] == "Insp. Test" for a in detail["actions"])
    assert client.post(f"/api/alerts/{aid}/action", json={"action": "bogus"}, headers=H).status_code == 400
    assert client.get("/api/audit/verify", headers=H).json()["ok"] is True


def test_snapshot_and_report(client):
    alert = client.get("/api/alerts?alert_type=watchlist_match", headers=H).json()[0]
    snap = client.get(f"/api/alerts/{alert['id']}/snapshot", headers=H)
    assert snap.status_code == 200 and snap.headers["content-type"] == "image/jpeg"
    rep = client.get(f"/api/alerts/{alert['id']}/report?api_key={API_KEY}")
    assert rep.status_code == 200 and "VERIFIED" in rep.text
    assert client.get(f"/api/reports/shift?api_key={API_KEY}").status_code == 200


def test_signed_evidence_bundle_roundtrip_and_tamper(client):
    alert = client.get("/api/alerts?alert_type=watchlist_match", headers=H).json()[0]
    r = client.get(f"/api/alerts/{alert['id']}/evidence", headers=H)
    assert r.status_code == 200
    ok = client.post("/api/evidence/verify", files={"file": ("b.zip", r.content, "application/zip")}, headers=H).json()
    assert ok["ok"] and ok["signature_valid"] and ok["files_ok"]

    src = zipfile.ZipFile(io.BytesIO(r.content))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for info in src.infolist():
            data = src.read(info)
            if info.filename.endswith("alert.json"):
                data = data.replace(b"critical", b"low")
            z.writestr(info.filename, data)
    bad = client.post("/api/evidence/verify", files={"file": ("b.zip", out.getvalue(), "application/zip")}, headers=H).json()
    assert bad["ok"] is False and bad["signature_valid"] is True
    assert any(f["file"] == "alert.json" and f["status"] == "MODIFIED" for f in bad["files"])

    # Raw byte flips inside a file's compressed data must be reported, not
    # crash. (A flip in header metadata such as an entry's timestamp leaves
    # every file's content intact, so the bundle rightly still verifies.)
    import struct
    for info in src.infolist():
        if info.compress_size < 8:
            continue
        name_len, extra_len = struct.unpack("<HH", r.content[info.header_offset + 26:info.header_offset + 30])
        pos = info.header_offset + 30 + name_len + extra_len + info.compress_size // 2
        flipped = bytearray(r.content)
        flipped[pos] ^= 0x01
        res = client.post("/api/evidence/verify", files={"file": ("f.zip", bytes(flipped), "application/zip")}, headers=H)
        assert res.status_code == 200 and res.json()["ok"] is False


def test_attack1_visible_edit_caught_by_row_check(client):
    client.post("/api/audit/demo/seed", headers=H)
    assert client.get("/api/audit/verify", headers=H).json()["ok"] is True
    client.post("/api/audit/demo/attack1", headers=H)
    v = client.get("/api/audit/verify", headers=H).json()
    assert v["ok"] is False and v["integrity"]["tampered_alert_ids"]


def test_attack2_record_rewrite_caught_by_chain(client):
    client.post("/api/audit/demo/seed", headers=H)
    client.post("/api/audit/demo/attack2", headers=H)
    v = client.get("/api/audit/verify", headers=H).json()
    assert v["ok"] is False and v["chain"]["chain_intact"] is False


def test_attack3_full_forgery_only_caught_by_signed_checkpoint(client):
    client.post("/api/audit/demo/seed", headers=H)
    r = client.post("/api/audit/demo/attack3", headers=H).json()
    assert r["records_recomputed"] >= 2
    v = client.get("/api/audit/verify", headers=H).json()
    assert v["chain"]["chain_intact"] is True            # the plain chain is fooled
    assert not v["integrity"]["tampered_alert_ids"]       # so is the row check
    assert v["checkpoints"]["ok"] is False and v["ok"] is False   # the signature is not


def test_integrity_report_explains_each_attack(client):
    report = lambda: client.get(f"/api/audit/report?api_key={API_KEY}").text  # noqa: E731
    client.post("/api/audit/demo/seed", headers=H)
    clean = report()
    assert "NO TAMPERING DETECTED" in clean and "This report is signed" in clean

    client.post("/api/audit/demo/attack1", headers=H)
    r1 = report()
    assert "TAMPERING DETECTED by: row snapshots" in r1 and "Altered rows" in r1
    assert "Routine patrol vehicle" in r1          # the forged live value is shown next to the original

    client.post("/api/audit/demo/seed", headers=H)
    client.post("/api/audit/demo/attack2", headers=H)
    r2 = report()
    assert "hash chain" in r2 and "Broken link" in r2 and "prev_hash does not equal" in r2

    client.post("/api/audit/demo/seed", headers=H)
    client.post("/api/audit/demo/attack3", headers=H)
    r3 = report()
    assert "TAMPERING DETECTED by: signed checkpoints" in r3
    assert "Only the signed checkpoints" in r3 and "Broken link" not in r3


def test_reset_starts_fresh_signed_chain(client):
    client.post("/api/data/reset", headers=H)
    v = client.get("/api/audit/verify", headers=H).json()
    assert v["ok"] is True and v["checkpoints"]["total"] == 1
    assert len(client.get("/api/intel/watchlist", headers=H).json()) >= 3


def test_watchlist_crud_and_fuzzy_match(client):
    r = client.post("/api/intel/watchlist", json={"plate": "mh-12 ab 1234", "reason": "test entry"}, headers=H)
    assert r.status_code == 200 and r.json()["plate"] == "MH12AB1234" and r.json()["format_valid"]
    m = client.get("/api/intel/match?plate=MH12A81234", headers=H).json()
    assert m["match"] == {"plate": "MH12AB1234", "type": "lookalike"}
    assert client.delete("/api/intel/watchlist/MH12AB1234", headers=H).status_code == 200
    assert client.delete("/api/intel/watchlist/MH12AB1234", headers=H).status_code == 404


def test_zones_persist(client):
    body = {"zones": [{"name": "Test Zone", "polygon": [[0, 0], [100, 0], [100, 100]]}],
            "lines": [{"name": "Test Line", "p1": [50, 0], "p2": [50, 540], "unauthorized_side": "b_to_a"}],
            "replace": True}
    r = client.post("/api/zones/cam-04", json=body, headers=H).json()
    assert r["zones"][0]["name"] == "Test Zone" and r["lines"][0]["unauthorized_side"] == "b_to_a"
    from app.core.storage import load_zones
    assert load_zones("cam-04")["lines"][0]["name"] == "Test Line"
    r = client.delete("/api/zones/cam-04", headers=H).json()
    assert r["lines"][0]["name"] == "Sector 7 Boundary"


def test_threat_and_system(client):
    t = client.get("/api/analytics/threat", headers=H).json()
    assert set(t["cameras"]) == {"cam-01", "cam-02", "cam-03", "cam-04"}
    assert t["site"]["level"] in ("LOW", "GUARDED", "ELEVATED", "CRITICAL")
    s = client.get("/api/system/status", headers=H).json()
    assert s["signing_key"]["algorithm"] == "Ed25519"
    assert client.get("/api/analytics/timeline?minutes=10", headers=H).status_code == 200
