"""
storage.py
----------
Persistence for IBVAP (stdlib sqlite3, WAL mode) with three layers of
tamper evidence:

  1. Hash chain (`audit_log`). Every alert, event, operator action and
     watchlist change is appended as a record whose SHA-256 covers the
     previous record's hash. Editing any record breaks every link after it.
  2. Row snapshots. Each alert/event row stores the id of its own audit
     record (`audit_id`), so an edit to the visible table that leaves the
     chain alone is caught by comparing the row with its snapshot.
  3. Signed checkpoints (`checkpoints`). Every CHECKPOINT_EVERY records the
     current chain head is signed with an Ed25519 key held outside the
     database. An insider who edits a record AND recomputes every later hash
     produces a chain that looks valid, but it no longer matches the signed
     head, and the signature cannot be forged without the key.

Alert *status* (new -> acknowledged -> investigating -> escalated ->
resolved / false positive) is mutable by design, but every change is an
`alert_actions` row that is itself chained, so the chain of custody is
tamper-evident even though the current status can move.

Two clocks are stored on purpose: `timestamp` is stream time (seconds into a
video or simulation, used by dwell-time logic), `created_at` is wall-clock
time (used for sorting, the timeline and the threat score).

Plain SQL, no ORM, so a move to Postgres/Timescale is a driver swap.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from app.config import CHECKPOINT_EVERY, DB_PATH, SNAPSHOT_DIR
from app.core import crypto
from app.core.analytics import Alert

GENESIS_HASH = "0" * 64
ALERT_STATUSES = ("new", "acknowledged", "investigating", "escalated", "resolved", "false_positive")

# Listeners are called (outside the write lock) after an alert is stored.
# hub.py registers one to push alerts to every connected dashboard.
_alert_listeners: List[Any] = []


def on_alert_saved(fn) -> None:
    _alert_listeners.append(fn)


def _notify(alert_row: dict) -> None:
    for fn in list(_alert_listeners):
        try:
            fn(alert_row)
        except Exception:  # noqa: BLE001 - a broken listener must never block storage
            pass


# ---- connections --------------------------------------------------------
def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.row_factory = sqlite3.Row
    return conn


# SQLite allows one writer at a time. Every write in this process goes through
# one connection guarded by a Python lock, so writes queue in memory instead of
# fighting over the file lock (which caused "database is locked" under load).
_write_lock = threading.RLock()
_write_conn: Optional[sqlite3.Connection] = None


def _wconn() -> sqlite3.Connection:
    global _write_conn
    if _write_conn is None:
        _write_conn = get_conn()
    return _write_conn


def _rows(sql: str, params: tuple | list = ()) -> List[dict]:
    conn = get_conn()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _one(sql: str, params: tuple | list = ()) -> Optional[dict]:
    rows = _rows(sql, params)
    return rows[0] if rows else None


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, coltype: str) -> None:
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    track_ids TEXT NOT NULL,
    camera_id TEXT NOT NULL,
    location_x REAL,
    location_y REAL,
    timestamp REAL NOT NULL,
    created_at REAL NOT NULL,
    plate TEXT,
    snapshot_hash TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    assignee TEXT,
    acknowledged INTEGER DEFAULT 0,
    audit_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_camera ON alerts(camera_id);

CREATE TABLE IF NOT EXISTS alert_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    operator TEXT NOT NULL,
    note TEXT,
    created_at REAL NOT NULL,
    audit_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_actions_alert ON alert_actions(alert_id);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    camera_id TEXT NOT NULL,
    details TEXT NOT NULL,
    timestamp REAL NOT NULL,
    created_at REAL NOT NULL,
    audit_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

CREATE TABLE IF NOT EXISTS session_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    people_count INTEGER NOT NULL,
    vehicle_count INTEGER DEFAULT 0,
    frame_index INTEGER NOT NULL,
    night_mode INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_stats_camera ON session_stats(camera_id, created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp REAL NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upto_audit_id INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    created_at REAL NOT NULL,
    key_fingerprint TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist (
    plate TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'high',
    added_by TEXT NOT NULL,
    added_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS plate_sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate TEXT NOT NULL,
    raw_text TEXT,
    camera_id TEXT NOT NULL,
    track_id INTEGER,
    confidence REAL,
    source TEXT NOT NULL,
    format_valid INTEGER DEFAULT 0,
    watchlist_plate TEXT,
    match_type TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sightings_plate ON plate_sightings(plate);

CREATE TABLE IF NOT EXISTS camera_zones (
    camera_id TEXT PRIMARY KEY,
    geometry_json TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

DEMO_WATCHLIST = [
    ("WB74AK2231", "Flagged in inter-agency bulletin: suspected cross-border smuggling (demo data)", "critical"),
    ("AS01BC9087", "Reported stolen, FIR on record (demo data)", "high"),
    ("21BH4521KX", "Vehicle of interest: repeated night movement near BOP (demo data)", "high"),
]


def init_db() -> None:
    with _write_lock:
        conn = _wconn()
        conn.executescript(SCHEMA)
        _ensure_column(conn, "alerts", "plate", "TEXT")
        conn.execute("""
            CREATE VIEW IF NOT EXISTS audit_trail_readable AS
            SELECT id, record_type, substr(payload, 1, 90) AS payload_preview,
                   datetime(timestamp, 'unixepoch', 'localtime') AS logged_at,
                   substr(prev_hash, 1, 12) || '...' AS prev_hash_short,
                   substr(hash, 1, 12) || '...' AS hash_short, prev_hash, hash
            FROM audit_log ORDER BY id
        """)
        conn.commit()
        if conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0] == 0:
            for plate, reason, prio in DEMO_WATCHLIST:
                _watchlist_add_locked(conn, plate, reason, prio, "system-seed")
            conn.commit()
        # A fresh database gets its first signed checkpoint immediately, so the
        # chain is anchored from the first record rather than after 25.
        if conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] == 0 \
                and conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] > 0:
            _write_checkpoint_locked(conn)
            conn.commit()
    crypto.public_key()  # create the signing key on first start


# ---- evidence snapshots -------------------------------------------------
def save_snapshot_file(image_bytes: bytes) -> str:
    """Content-addressed by SHA-256, so the hash exists before the alert row
    and goes into the same chained payload as the alert text."""
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256(image_bytes).hexdigest()
    path = SNAPSHOT_DIR / f"{h}.jpg"
    if not path.exists():
        path.write_bytes(image_bytes)
    return h


# ---- hash chain ---------------------------------------------------------
def compute_hash(prev_hash: str, record_type: str, payload_json: str, timestamp: float) -> str:
    canonical = f"{prev_hash}|{record_type}|{payload_json}|{timestamp}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _append_audit(conn: sqlite3.Connection, record_type: str, payload: dict, ts: float) -> int:
    row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["hash"] if row else GENESIS_HASH
    payload_json = json.dumps(payload, sort_keys=True)
    h = compute_hash(prev_hash, record_type, payload_json, ts)
    cur = conn.execute(
        "INSERT INTO audit_log (record_type, payload, timestamp, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
        (record_type, payload_json, ts, prev_hash, h),
    )
    return int(cur.lastrowid)


def _checkpoint_message(upto: int, head: str, count: int, created_at: float) -> bytes:
    return f"IBVAP-CHECKPOINT|{upto}|{head}|{count}|{created_at:.6f}".encode("ascii")


def _write_checkpoint_locked(conn: sqlite3.Connection) -> Optional[dict]:
    head = conn.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    if not head:
        return None
    count = conn.execute("SELECT COUNT(*) FROM audit_log WHERE id <= ?", (head["id"],)).fetchone()[0]
    now = time.time()
    sig = crypto.sign(_checkpoint_message(head["id"], head["hash"], count, now))
    cur = conn.execute(
        """INSERT INTO checkpoints (upto_audit_id, head_hash, record_count, created_at, key_fingerprint, signature)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (head["id"], head["hash"], count, now, crypto.key_fingerprint(), sig),
    )
    return {"id": cur.lastrowid, "upto_audit_id": head["id"], "head_hash": head["hash"],
            "record_count": count, "created_at": now}


def _maybe_checkpoint_locked(conn: sqlite3.Connection) -> None:
    last = conn.execute("SELECT MAX(upto_audit_id) FROM checkpoints").fetchone()[0] or 0
    head = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0] or 0
    if head - last >= CHECKPOINT_EVERY:
        _write_checkpoint_locked(conn)


def create_checkpoint() -> Optional[dict]:
    with _write_lock:
        conn = _wconn()
        cp = _write_checkpoint_locked(conn)
        conn.commit()
        return cp


# ---- alerts -------------------------------------------------------------
def _alert_payload(row: dict) -> dict:
    return {k: row.get(k) for k in (
        "id", "alert_type", "severity", "message", "track_ids", "camera_id",
        "location_x", "location_y", "timestamp", "created_at", "plate", "snapshot_hash",
    )}


def save_alert(alert: Alert, snapshot_hash: Optional[str] = None) -> int:
    loc = alert.location or (None, None)
    track_ids_str = ",".join(map(str, alert.track_ids))
    now = time.time()
    with _write_lock:
        conn = _wconn()
        cur = conn.execute(
            """INSERT INTO alerts (alert_type, severity, message, track_ids, camera_id,
                   location_x, location_y, timestamp, created_at, plate, snapshot_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert.alert_type, alert.severity, alert.message, track_ids_str, alert.camera_id,
             _f(loc[0]), _f(loc[1]), float(alert.timestamp), now, alert.plate, snapshot_hash),
        )
        alert_id = int(cur.lastrowid)
        row = {
            "id": alert_id, "alert_type": alert.alert_type, "severity": alert.severity,
            "message": alert.message, "track_ids": track_ids_str, "camera_id": alert.camera_id,
            "location_x": _f(loc[0]), "location_y": _f(loc[1]), "timestamp": float(alert.timestamp),
            "created_at": now, "plate": alert.plate, "snapshot_hash": snapshot_hash,
        }
        audit_id = _append_audit(conn, "alert", _alert_payload(row), now)
        conn.execute("UPDATE alerts SET audit_id = ? WHERE id = ?", (audit_id, alert_id))
        _maybe_checkpoint_locked(conn)
        conn.commit()
    row.update({"status": "new", "acknowledged": 0, "assignee": None, "audit_id": audit_id})
    _notify(row)
    return alert_id


def _f(v) -> Optional[float]:
    return None if v is None else round(float(v), 2)


def fetch_alerts(limit: int = 100, severity: Optional[str] = None, camera_id: Optional[str] = None,
                 status: Optional[str] = None, alert_type: Optional[str] = None,
                 since: Optional[float] = None, q: Optional[str] = None) -> List[dict]:
    clauses, params = [], []
    for col, val in (("severity", severity), ("camera_id", camera_id), ("status", status),
                     ("alert_type", alert_type)):
        if val:
            clauses.append(f"{col} = ?")
            params.append(val)
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if q:
        clauses.append("(message LIKE ? OR plate LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(clauses) if clauses else "")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    return _rows(sql, params)


def fetch_alert_by_id(alert_id: int) -> Optional[dict]:
    return _one("SELECT * FROM alerts WHERE id = ?", (alert_id,))


def fetch_alert_actions(alert_id: int) -> List[dict]:
    return _rows("SELECT * FROM alert_actions WHERE alert_id = ? ORDER BY id ASC", (alert_id,))


def record_alert_action(alert_id: int, action: str, operator: str, note: Optional[str] = None,
                        assignee: Optional[str] = None) -> Optional[dict]:
    """Moves an alert through the incident workflow. `action` is a target
    status from ALERT_STATUSES or 'note' / 'assign'. Every call appends a
    chained audit record, so the custody trail cannot be silently edited."""
    if action not in ALERT_STATUSES + ("note", "assign"):
        raise ValueError(f"Unknown action {action!r}")
    now = time.time()
    with _write_lock:
        conn = _wconn()
        if not conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone():
            return None
        cur = conn.execute(
            "INSERT INTO alert_actions (alert_id, action, operator, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (alert_id, action, operator, note, now),
        )
        action_id = int(cur.lastrowid)
        audit_id = _append_audit(conn, "alert_action", {
            "id": action_id, "alert_id": alert_id, "action": action, "operator": operator,
            "note": note, "assignee": assignee, "created_at": now,
        }, now)
        conn.execute("UPDATE alert_actions SET audit_id = ? WHERE id = ?", (audit_id, action_id))
        if action in ALERT_STATUSES:
            conn.execute("UPDATE alerts SET status = ?, acknowledged = ? WHERE id = ?",
                         (action, 0 if action == "new" else 1, alert_id))
        if action == "assign" or assignee:
            conn.execute("UPDATE alerts SET assignee = ? WHERE id = ?", (assignee or operator, alert_id))
        _maybe_checkpoint_locked(conn)
        conn.commit()
    return {"id": action_id, "alert_id": alert_id, "action": action, "operator": operator,
            "note": note, "created_at": now, "audit_id": audit_id}


def acknowledge_alert(alert_id: int, operator: str = "operator") -> bool:
    return record_alert_action(alert_id, "acknowledged", operator) is not None


# ---- events, stats ------------------------------------------------------
def save_event(event_type: str, camera_id: str, details: str, timestamp: Optional[float] = None) -> int:
    now = time.time()
    ts = float(timestamp) if timestamp is not None else now
    with _write_lock:
        conn = _wconn()
        cur = conn.execute(
            "INSERT INTO events (event_type, camera_id, details, timestamp, created_at) VALUES (?, ?, ?, ?, ?)",
            (event_type, camera_id, details, ts, now),
        )
        event_id = int(cur.lastrowid)
        audit_id = _append_audit(conn, "event", {
            "id": event_id, "event_type": event_type, "camera_id": camera_id,
            "details": details, "timestamp": ts, "created_at": now,
        }, now)
        conn.execute("UPDATE events SET audit_id = ? WHERE id = ?", (audit_id, event_id))
        _maybe_checkpoint_locked(conn)
        conn.commit()
    return event_id


def fetch_events(limit: int = 100, event_type: Optional[str] = None,
                 camera_id: Optional[str] = None) -> List[dict]:
    clauses, params = [], []
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if camera_id:
        clauses.append("camera_id = ?")
        params.append(camera_id)
    sql = "SELECT * FROM events" + (" WHERE " + " AND ".join(clauses) if clauses else "")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    return _rows(sql, params)


def save_stat(camera_id: str, people_count: int, frame_index: int,
              vehicle_count: int = 0, night_mode: bool = False) -> None:
    with _write_lock:
        conn = _wconn()
        conn.execute(
            """INSERT INTO session_stats (camera_id, created_at, people_count, vehicle_count, frame_index, night_mode)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (camera_id, time.time(), people_count, vehicle_count, frame_index, 1 if night_mode else 0),
        )
        conn.commit()


# ---- watchlist + ANPR sightings ----------------------------------------
def _watchlist_add_locked(conn, plate: str, reason: str, priority: str, added_by: str) -> None:
    now = time.time()
    conn.execute(
        "INSERT OR REPLACE INTO watchlist (plate, reason, priority, added_by, added_at) VALUES (?, ?, ?, ?, ?)",
        (plate, reason, priority, added_by, now),
    )
    _append_audit(conn, "watchlist_add", {"plate": plate, "reason": reason, "priority": priority,
                                          "added_by": added_by, "added_at": now}, now)


def watchlist_add(plate: str, reason: str, priority: str = "high", added_by: str = "operator") -> dict:
    with _write_lock:
        conn = _wconn()
        _watchlist_add_locked(conn, plate, reason, priority, added_by)
        conn.commit()
    return {"plate": plate, "reason": reason, "priority": priority, "added_by": added_by}


def watchlist_remove(plate: str, removed_by: str = "operator") -> bool:
    now = time.time()
    with _write_lock:
        conn = _wconn()
        cur = conn.execute("DELETE FROM watchlist WHERE plate = ?", (plate,))
        if cur.rowcount:
            _append_audit(conn, "watchlist_remove", {"plate": plate, "removed_by": removed_by,
                                                     "removed_at": now}, now)
        conn.commit()
        return cur.rowcount > 0


def fetch_watchlist() -> List[dict]:
    rows = _rows("SELECT * FROM watchlist ORDER BY added_at DESC")
    hits = {r["watchlist_plate"]: r for r in _rows(
        """SELECT watchlist_plate, COUNT(*) AS hits, MAX(created_at) AS last_seen,
                  (SELECT camera_id FROM plate_sightings s2 WHERE s2.watchlist_plate = s.watchlist_plate
                   ORDER BY id DESC LIMIT 1) AS last_camera
           FROM plate_sightings s WHERE watchlist_plate IS NOT NULL GROUP BY watchlist_plate""")}
    for r in rows:
        h = hits.get(r["plate"])
        r["hits"] = h["hits"] if h else 0
        r["last_seen"] = h["last_seen"] if h else None
        r["last_camera"] = h["last_camera"] if h else None
    return rows


def watchlist_plates() -> List[str]:
    return [r["plate"] for r in _rows("SELECT plate FROM watchlist")]


def watchlist_entry(plate: str) -> Optional[dict]:
    return _one("SELECT * FROM watchlist WHERE plate = ?", (plate,))


def save_sighting(plate: str, raw_text: str, camera_id: str, track_id: int, confidence: float,
                  source: str, format_valid: bool, watchlist_plate: Optional[str],
                  match_type: Optional[str]) -> int:
    with _write_lock:
        conn = _wconn()
        cur = conn.execute(
            """INSERT INTO plate_sightings (plate, raw_text, camera_id, track_id, confidence, source,
                   format_valid, watchlist_plate, match_type, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plate, raw_text, camera_id, track_id, round(float(confidence), 3), source,
             1 if format_valid else 0, watchlist_plate, match_type, time.time()),
        )
        conn.commit()
        return int(cur.lastrowid)


def fetch_plates(limit: int = 200, q: Optional[str] = None) -> List[dict]:
    where, params = "", []
    if q:
        where = "WHERE plate LIKE ?"
        params.append(f"%{q.upper()}%")
    params.append(int(limit))
    return _rows(f"""
        SELECT plate, COUNT(*) AS sightings, COUNT(DISTINCT camera_id) AS cameras,
               MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
               MAX(format_valid) AS format_valid, MAX(watchlist_plate) AS watchlist_plate,
               MAX(source) AS source
        FROM plate_sightings {where}
        GROUP BY plate ORDER BY last_seen DESC LIMIT ?""", params)


def fetch_trajectory(plate: str) -> List[dict]:
    return _rows("SELECT * FROM plate_sightings WHERE plate = ? ORDER BY created_at ASC", (plate.upper(),))


# ---- zones --------------------------------------------------------------
def save_zones(camera_id: str, geometry: dict) -> None:
    with _write_lock:
        conn = _wconn()
        conn.execute("INSERT OR REPLACE INTO camera_zones (camera_id, geometry_json, updated_at) VALUES (?, ?, ?)",
                     (camera_id, json.dumps(geometry), time.time()))
        conn.commit()


def load_zones(camera_id: str) -> Optional[dict]:
    row = _one("SELECT geometry_json FROM camera_zones WHERE camera_id = ?", (camera_id,))
    return json.loads(row["geometry_json"]) if row else None


# ---- analytics ----------------------------------------------------------
def fetch_summary(camera_id: Optional[str] = None, since: Optional[float] = None) -> dict:
    clauses, params = [], []
    if camera_id:
        clauses.append("camera_id = ?")
        params.append(camera_id)
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_conn()
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0]
        by_type = dict(conn.execute(f"SELECT alert_type, COUNT(*) FROM alerts{where} GROUP BY alert_type", params).fetchall())
        by_sev = dict(conn.execute(f"SELECT severity, COUNT(*) FROM alerts{where} GROUP BY severity", params).fetchall())
        by_status = dict(conn.execute(f"SELECT status, COUNT(*) FROM alerts{where} GROUP BY status", params).fetchall())
        by_cam = dict(conn.execute(f"SELECT camera_id, COUNT(*) FROM alerts{where} GROUP BY camera_id", params).fetchall())
        st = conn.execute(f"""SELECT MAX(people_count), AVG(people_count), MAX(vehicle_count), AVG(vehicle_count)
                              FROM session_stats{where}""", params).fetchone()
        ev = dict(conn.execute(f"SELECT event_type, COUNT(*) FROM events{where} GROUP BY event_type", params).fetchall())
        plates = conn.execute(f"SELECT COUNT(DISTINCT plate) FROM plate_sightings{where}", params).fetchone()[0]
        wl_hits = conn.execute(
            f"SELECT COUNT(*) FROM plate_sightings{where}{' AND' if where else ' WHERE'} watchlist_plate IS NOT NULL",
            params).fetchone()[0]
        open_cases = conn.execute(
            f"SELECT COUNT(*) FROM alerts{where}{' AND' if where else ' WHERE'} status NOT IN ('resolved','false_positive')",
            params).fetchone()[0]
        audit_records = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    return {
        "total_alerts": total, "open_alerts": open_cases,
        "by_type": by_type, "by_severity": by_sev, "by_status": by_status, "by_camera": by_cam,
        "events_by_type": ev,
        "peak_occupancy": st[0] or 0, "avg_occupancy": round(st[1] or 0, 2),
        "peak_vehicle_count": st[2] or 0, "avg_vehicle_count": round(st[3] or 0, 2),
        "unique_plates": plates, "watchlist_hits": wl_hits, "audit_records": audit_records,
    }


def fetch_timeline(minutes: int = 30, bucket_s: int = 60, camera_id: Optional[str] = None) -> dict:
    now = time.time()
    start = now - minutes * 60
    params: list = [start]
    cam = ""
    if camera_id:
        cam = " AND camera_id = ?"
        params.append(camera_id)
    rows = _rows(f"SELECT created_at AS t, severity FROM alerts WHERE created_at >= ?{cam}", params)
    n = max(1, int(minutes * 60 // bucket_s))
    buckets = [{"t": start + i * bucket_s, "low": 0, "medium": 0, "high": 0, "critical": 0} for i in range(n)]
    for r in rows:
        i = min(n - 1, int((r["t"] - start) // bucket_s))
        if 0 <= i < n and r["severity"] in buckets[i]:
            buckets[i][r["severity"]] += 1
    return {"bucket_seconds": bucket_s, "buckets": buckets}


def fetch_occupancy_series(camera_id: str, minutes: int = 10) -> List[dict]:
    return _rows("""SELECT created_at, people_count, vehicle_count, night_mode FROM session_stats
                    WHERE camera_id = ? AND created_at >= ? ORDER BY id ASC""",
                 (camera_id, time.time() - minutes * 60))


def recent_alerts_for_threat(window_s: float = 600) -> List[dict]:
    return _rows("SELECT camera_id, severity, created_at, status FROM alerts WHERE created_at >= ?",
                 (time.time() - window_s,))


# ---- verification -------------------------------------------------------
def verify_chain() -> dict:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    prev = GENESIS_HASH
    for row in rows:
        expected = compute_hash(prev, row["record_type"], row["payload"], row["timestamp"])
        if row["prev_hash"] != prev or row["hash"] != expected:
            return {"chain_intact": False, "broken_at_id": row["id"], "records_checked": len(rows),
                    "head_hash": None}
        prev = row["hash"]
    return {"chain_intact": True, "broken_at_id": None, "records_checked": len(rows),
            "head_hash": prev if rows else None}


def _live_alert_row(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}


def verify_integrity(check_last: int = 500) -> dict:
    conn = get_conn()
    tampered_alerts, tampered_events, tampered_actions = [], [], []
    try:
        for table, bucket in (("alerts", tampered_alerts), ("events", tampered_events),
                              ("alert_actions", tampered_actions)):
            for row in conn.execute(
                    f"SELECT * FROM {table} WHERE audit_id IS NOT NULL ORDER BY id DESC LIMIT ?", (check_last,)):
                audit_row = conn.execute("SELECT payload FROM audit_log WHERE id = ?", (row["audit_id"],)).fetchone()
                if not audit_row:
                    bucket.append(row["id"])
                    continue
                snap = json.loads(audit_row["payload"])
                live = _live_alert_row(row)
                # Compare every field the chained snapshot committed to.
                if any(live.get(k) != v for k, v in snap.items() if k in live):
                    bucket.append(row["id"])
    finally:
        conn.close()
    return {"tampered_alert_ids": tampered_alerts, "tampered_event_ids": tampered_events,
            "tampered_action_ids": tampered_actions, "records_checked": check_last}


def verify_checkpoints() -> dict:
    conn = get_conn()
    try:
        cps = conn.execute("SELECT * FROM checkpoints ORDER BY id ASC").fetchall()
        failed = []
        for cp in cps:
            msg = _checkpoint_message(cp["upto_audit_id"], cp["head_hash"], cp["record_count"], cp["created_at"])
            reason = None
            if not crypto.verify(msg, cp["signature"]):
                reason = "signature invalid"
            else:
                row = conn.execute("SELECT hash FROM audit_log WHERE id = ?", (cp["upto_audit_id"],)).fetchone()
                count = conn.execute("SELECT COUNT(*) FROM audit_log WHERE id <= ?", (cp["upto_audit_id"],)).fetchone()[0]
                if row is None:
                    reason = "signed record deleted"
                elif row["hash"] != cp["head_hash"]:
                    reason = "chain head no longer matches signed hash"
                elif count != cp["record_count"]:
                    reason = "records deleted before checkpoint"
            if reason:
                failed.append({"checkpoint_id": cp["id"], "upto_audit_id": cp["upto_audit_id"], "reason": reason})
        latest = dict(cps[-1]) if cps else None
    finally:
        conn.close()
    return {"ok": not failed, "total": len(cps), "failed": failed, "latest": latest,
            "key_fingerprint": crypto.key_fingerprint()}


def verify_all() -> dict:
    chain = verify_chain()
    integrity = verify_integrity()
    checkpoints = verify_checkpoints()
    ok = (chain["chain_intact"] and checkpoints["ok"] and not integrity["tampered_alert_ids"]
          and not integrity["tampered_event_ids"] and not integrity["tampered_action_ids"])
    return {"ok": ok, "chain": chain, "integrity": integrity, "checkpoints": checkpoints,
            "verified_at": time.time()}


def chain_break_detail(broken_at_id: int) -> Optional[dict]:
    """Explains a broken link: what the record stores versus what the
    chain math expects at that position."""
    rec = fetch_audit_record(broken_at_id)
    if rec is None:
        return None
    prev = _one("SELECT id, hash FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT 1", (broken_at_id,))
    expected_prev = prev["hash"] if prev else GENESIS_HASH
    recomputed = compute_hash(rec["prev_hash"], rec["record_type"], rec["payload"], rec["timestamp"])
    if rec["prev_hash"] != expected_prev:
        reason = (f"Its prev_hash does not equal the hash of record #{prev['id'] if prev else 0}. "
                  "An earlier record was changed after this one was written.")
    else:
        reason = "Its stored hash does not match a recomputation of its own contents. This record itself was edited."
    try:
        payload = json.loads(rec["payload"])
    except json.JSONDecodeError:
        payload = rec["payload"]
    return {"audit_id": broken_at_id, "record_type": rec["record_type"], "reason": reason,
            "stored_prev_hash": rec["prev_hash"], "expected_prev_hash": expected_prev,
            "stored_hash": rec["hash"], "recomputed_hash": recomputed, "payload": payload,
            "previous_record_id": prev["id"] if prev else None}


def row_tamper_details(table: str, ids: List[int], limit: int = 20) -> List[dict]:
    """Field-by-field diff between the live row and its chained snapshot."""
    if table not in ("alerts", "events", "alert_actions"):
        raise ValueError(table)
    out = []
    conn = get_conn()
    try:
        for rid in ids[:limit]:
            row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (rid,)).fetchone()
            if row is None:
                continue
            audit = conn.execute("SELECT payload FROM audit_log WHERE id = ?", (row["audit_id"],)).fetchone()
            if audit is None:
                out.append({"table": table, "id": rid, "audit_id": row["audit_id"],
                            "changes": [{"field": "(audit record)", "chained": "missing", "live": "row still present"}]})
                continue
            snap = json.loads(audit["payload"])
            live = {k: row[k] for k in row.keys()}
            changes = [{"field": k, "chained": v, "live": live.get(k)}
                       for k, v in snap.items() if k in live and live.get(k) != v]
            out.append({"table": table, "id": rid, "audit_id": row["audit_id"], "changes": changes})
    finally:
        conn.close()
    return out


def checkpoint_report(limit: int = 15) -> List[dict]:
    """Every recent checkpoint with what it signed and what is there now."""
    out = []
    conn = get_conn()
    try:
        for cp in conn.execute("SELECT * FROM checkpoints ORDER BY id DESC LIMIT ?", (limit,)).fetchall():
            msg = _checkpoint_message(cp["upto_audit_id"], cp["head_hash"], cp["record_count"], cp["created_at"])
            sig_ok = crypto.verify(msg, cp["signature"])
            row = conn.execute("SELECT hash FROM audit_log WHERE id = ?", (cp["upto_audit_id"],)).fetchone()
            count = conn.execute("SELECT COUNT(*) FROM audit_log WHERE id <= ?", (cp["upto_audit_id"],)).fetchone()[0]
            current = row["hash"] if row else None
            ok = sig_ok and current == cp["head_hash"] and count == cp["record_count"]
            out.append({"id": cp["id"], "upto_audit_id": cp["upto_audit_id"], "created_at": cp["created_at"],
                        "signed_head_hash": cp["head_hash"], "current_hash": current,
                        "signed_count": cp["record_count"], "current_count": count,
                        "signature_valid": sig_ok, "ok": ok})
    finally:
        conn.close()
    return out


def fetch_audit_records(limit: int = 50, before_id: Optional[int] = None) -> List[dict]:
    if before_id:
        return _rows("SELECT * FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?", (before_id, limit))
    return _rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


def fetch_audit_record(audit_id: int) -> Optional[dict]:
    return _one("SELECT * FROM audit_log WHERE id = ?", (audit_id,))


def fetch_checkpoints(limit: int = 20) -> List[dict]:
    return _rows("SELECT * FROM checkpoints ORDER BY id DESC LIMIT ?", (limit,))


def db_stats() -> dict:
    size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    wal = DB_PATH.with_name(DB_PATH.name + "-wal")
    size += wal.stat().st_size if wal.exists() else 0
    counts = {}
    for t in ("alerts", "events", "audit_log", "checkpoints", "plate_sightings", "watchlist", "alert_actions"):
        r = _one(f"SELECT COUNT(*) AS c FROM {t}")
        counts[t] = r["c"] if r else 0
    snaps = list(SNAPSHOT_DIR.glob("*.jpg")) if SNAPSHOT_DIR.exists() else []
    return {"db_bytes": size, "snapshots": len(snaps), "counts": counts}


# ---- reset + tamper demo -----------------------------------------------
_TRACKING_TABLES = ("alerts", "alert_actions", "events", "audit_log", "session_stats",
                    "checkpoints", "plate_sightings")


def _wipe_locked(conn) -> None:
    for t in _TRACKING_TABLES:
        conn.execute(f"DELETE FROM {t}")
    names = ",".join(f"'{t}'" for t in _TRACKING_TABLES)
    conn.execute(f"DELETE FROM sqlite_sequence WHERE name IN ({names})")


def reset_all_data() -> dict:
    """Clears tracking data for a clean demo. The watchlist is kept, and its
    entries are re-anchored as the first records of the new chain."""
    with _write_lock:
        conn = _wconn()
        _wipe_locked(conn)
        for w in conn.execute("SELECT * FROM watchlist").fetchall():
            _append_audit(conn, "watchlist_add", {"plate": w["plate"], "reason": w["reason"],
                                                  "priority": w["priority"], "added_by": w["added_by"],
                                                  "added_at": w["added_at"]}, w["added_at"])
        _write_checkpoint_locked(conn)
        conn.commit()
    return {"status": "reset", "message": "Tracking data cleared. A fresh signed chain has started."}


DEMO_CAMERA_ID = "cam-tamper-demo"


def seed_tamper_demo() -> dict:
    with _write_lock:
        conn = _wconn()
        _wipe_locked(conn)
        conn.commit()
    demo = [
        Alert("unauthorized_crossing", "critical", "Person #1 crossed 'Border Fence Line' in unauthorized direction",
              [1], 12.0, DEMO_CAMERA_ID),
        Alert("group_formation", "high", "Unusual cluster of persons (3) formed near restricted zone",
              [2, 3, 4], 21.0, DEMO_CAMERA_ID),
        Alert("loitering", "medium", "Person #5 loitering in restricted zone for 12s", [5], 30.0, DEMO_CAMERA_ID),
        Alert("watchlist_match", "critical", "Watchlisted vehicle WB74AK2231 sighted (exact match)",
              [6], 41.0, DEMO_CAMERA_ID, plate="WB74AK2231"),
    ]
    for a in demo:
        save_alert(a)
    save_event("anpr_read", DEMO_CAMERA_ID, "Vehicle #6 plate read: WB74AK2231", 40.0)
    save_event("face_detected", DEMO_CAMERA_ID, "Face detected on person #2", 22.0)
    cp = create_checkpoint()
    return {
        "seeded_alerts": _rows("SELECT id, alert_type, severity, message FROM alerts WHERE camera_id = ? ORDER BY id",
                               (DEMO_CAMERA_ID,)),
        "seeded_events": _rows("SELECT id, event_type, details FROM events WHERE camera_id = ? ORDER BY id",
                               (DEMO_CAMERA_ID,)),
        "checkpoint": cp,
    }


def simulate_visible_edit_attack() -> dict:
    """Attack 1: edit the visible alerts table, leave the chain alone."""
    row = _one("SELECT id, message, severity FROM alerts WHERE camera_id = ? ORDER BY id DESC LIMIT 1",
               (DEMO_CAMERA_ID,))
    if not row:
        return {"error": "No demo data seeded yet -- call seed first."}
    new_msg, new_sev = "Routine patrol vehicle -- no action needed", "low"
    with _write_lock:
        conn = _wconn()
        conn.execute("UPDATE alerts SET message = ?, severity = ? WHERE id = ?", (new_msg, new_sev, row["id"]))
        conn.commit()
    return {"attack": "visible_edit", "target_alert_id": row["id"], "before": row,
            "after": {"id": row["id"], "message": new_msg, "severity": new_sev},
            "caught_by": "row-snapshot integrity check"}


def simulate_chain_rewrite_attack() -> dict:
    """Attack 2: edit one chained record and recompute ITS hash only."""
    row = _one("""SELECT audit_log.* FROM audit_log JOIN alerts ON alerts.audit_id = audit_log.id
                  WHERE alerts.camera_id = ? ORDER BY audit_log.id ASC LIMIT 1""", (DEMO_CAMERA_ID,))
    if not row:
        return {"error": "No demo data seeded yet -- call seed first."}
    payload = json.loads(row["payload"])
    before = dict(payload)
    payload["severity"], payload["message"] = "low", "Routine activity, no action needed"
    pj = json.dumps(payload, sort_keys=True)
    h = compute_hash(row["prev_hash"], row["record_type"], pj, row["timestamp"])
    with _write_lock:
        conn = _wconn()
        conn.execute("UPDATE audit_log SET payload = ?, hash = ? WHERE id = ?", (pj, h, row["id"]))
        conn.commit()
    return {"attack": "single_record_rewrite", "target_audit_log_id": row["id"], "before_payload": before,
            "after_payload": payload, "caught_by": "hash chain (next record's prev_hash)"}


def simulate_full_chain_forgery() -> dict:
    """Attack 3, the strongest insider attack: edit a record, then recompute
    EVERY later hash and patch the visible table to match. The plain hash
    chain and the row check both pass afterwards. Only the Ed25519-signed
    checkpoint, whose key is not in the database, can expose it."""
    target = _one("""SELECT alerts.id AS alert_id, audit_log.id AS audit_id FROM alerts
                     JOIN audit_log ON alerts.audit_id = audit_log.id
                     WHERE alerts.camera_id = ? ORDER BY alerts.id ASC LIMIT 1""", (DEMO_CAMERA_ID,))
    if not target:
        return {"error": "No demo data seeded yet -- call seed first."}
    new_msg, new_sev = "Authorised patrol crossing -- logged for reference", "low"
    with _write_lock:
        conn = _wconn()
        rows = conn.execute("SELECT * FROM audit_log WHERE id >= ? ORDER BY id ASC", (target["audit_id"],)).fetchall()
        prev = conn.execute("SELECT hash FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT 1",
                            (target["audit_id"],)).fetchone()
        prev_hash = prev["hash"] if prev else GENESIS_HASH
        before = json.loads(rows[0]["payload"])
        for r in rows:
            payload_json = r["payload"]
            if r["id"] == target["audit_id"]:
                p = json.loads(payload_json)
                p["message"], p["severity"] = new_msg, new_sev
                payload_json = json.dumps(p, sort_keys=True)
            h = compute_hash(prev_hash, r["record_type"], payload_json, r["timestamp"])
            conn.execute("UPDATE audit_log SET payload = ?, prev_hash = ?, hash = ? WHERE id = ?",
                         (payload_json, prev_hash, h, r["id"]))
            prev_hash = h
        conn.execute("UPDATE alerts SET message = ?, severity = ? WHERE id = ?",
                     (new_msg, new_sev, target["alert_id"]))
        conn.commit()
    return {"attack": "full_chain_forgery", "target_alert_id": target["alert_id"],
            "records_recomputed": len(rows), "before": {"message": before.get("message"),
                                                         "severity": before.get("severity")},
            "after": {"message": new_msg, "severity": new_sev},
            "caught_by": "Ed25519-signed checkpoint (hash chain alone is fooled)"}
