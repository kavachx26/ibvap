"""
evidence.py
-----------
Signed evidence bundles: one ZIP an investigator can take away and verify
without access to the IBVAP server.

Bundle contents
  alert.json          the alert row as stored
  custody.json        every workflow action (who, what, when, note)
  audit_record.json   the chained audit record for the alert, with its hashes
  chain_status.json   chain + checkpoint verification at export time
  snapshot.jpg        the evidence frame (if one was captured)
  public_key.pem      Ed25519 public key of this IBVAP installation
  manifest.json       SHA-256 of every file above, plus export metadata
  manifest.sig        Ed25519 signature over manifest.json
  VERIFY.txt          how to check the bundle by hand

verify_bundle() re-hashes every file, checks the manifest signature and
returns a per-file verdict. Changing one byte anywhere fails it.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from typing import Optional

from app.config import APP_NAME, APP_VERSION, SNAPSHOT_DIR
from app.core import crypto, storage

_VERIFY_TXT = """IBVAP signed evidence bundle
============================
1. Hash every file listed in manifest.json with SHA-256 and compare.
2. Verify manifest.sig (hex Ed25519 signature) over the exact bytes of
   manifest.json using public_key.pem. Example (Python, cryptography):

   from cryptography.hazmat.primitives import serialization
   pub = serialization.load_pem_public_key(open('public_key.pem','rb').read())
   pub.verify(bytes.fromhex(open('manifest.sig').read().strip()), open('manifest.json','rb').read())

3. The key fingerprint in manifest.json must match the fingerprint published
   by the IBVAP installation (GET /api/system/status -> signing_key).
Or upload the ZIP to IBVAP: Evidence & Audit -> Verify a bundle.
"""


def build_bundle(alert_id: int, exported_by: str = "operator") -> Optional[bytes]:
    alert = storage.fetch_alert_by_id(alert_id)
    if alert is None:
        return None
    files: dict[str, bytes] = {}
    files["alert.json"] = json.dumps(alert, indent=2, sort_keys=True).encode()
    files["custody.json"] = json.dumps(storage.fetch_alert_actions(alert_id), indent=2).encode()
    audit = storage.fetch_audit_record(alert["audit_id"]) if alert.get("audit_id") else None
    files["audit_record.json"] = json.dumps(audit, indent=2).encode()
    v = storage.verify_all()
    files["chain_status.json"] = json.dumps({
        "chain_intact": v["chain"]["chain_intact"], "records_checked": v["chain"]["records_checked"],
        "head_hash": v["chain"]["head_hash"], "checkpoints_ok": v["checkpoints"]["ok"],
        "checkpoints_total": v["checkpoints"]["total"],
        "this_alert_tampered": alert_id in v["integrity"]["tampered_alert_ids"],
    }, indent=2).encode()
    snap_ok = None
    if alert.get("snapshot_hash"):
        p = SNAPSHOT_DIR / f"{alert['snapshot_hash']}.jpg"
        if p.exists():
            data = p.read_bytes()
            snap_ok = hashlib.sha256(data).hexdigest() == alert["snapshot_hash"]
            files["snapshot.jpg"] = data
    files["public_key.pem"] = crypto.public_key_pem().encode()
    files["VERIFY.txt"] = _VERIFY_TXT.encode()

    manifest = {
        "product": f"{APP_NAME} {APP_VERSION}", "alert_id": alert_id, "exported_at": time.time(),
        "exported_by": exported_by, "key_fingerprint": crypto.key_fingerprint(),
        "snapshot_matches_chain_hash": snap_ok,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    files["manifest.json"] = manifest_bytes
    files["manifest.sig"] = crypto.sign(manifest_bytes).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(f"IBVAP_evidence_alert_{alert_id}/{name}", data)
    return buf.getvalue()


def verify_bundle(zip_bytes: bytes) -> dict:
    try:
        z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception:  # noqa: BLE001 - BadZipFile, or a damaged central directory
        return {"ok": False, "error": "Not a readable ZIP file (missing or damaged structure)."}
    contents = {}
    corrupted = []
    for info in z.infolist():
        if info.is_dir():
            continue
        try:
            contents[info.filename.split("/")[-1]] = z.read(info)
        except Exception:  # noqa: BLE001 - bad CRC / broken deflate stream = altered bytes
            corrupted.append(info.filename.split("/")[-1])
    if corrupted and ("manifest.json" in corrupted or "manifest.sig" in corrupted):
        return {"ok": False, "error": f"Bundle is corrupted: {', '.join(corrupted)} failed the ZIP integrity check "
                                      "(its bytes were altered).", "files": [], "signature_valid": False}
    if "manifest.json" not in contents or "manifest.sig" not in contents:
        return {"ok": False, "error": "manifest.json / manifest.sig missing -- not an IBVAP bundle."}
    manifest_bytes = contents["manifest.json"]
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        return {"ok": False, "error": "manifest.json is not valid JSON."}
    pem = contents.get("public_key.pem", b"").decode(errors="replace")
    sig_ok = crypto.verify(manifest_bytes, contents["manifest.sig"].decode().strip(), pem=pem or None)
    trusted_key = manifest.get("key_fingerprint") == crypto.key_fingerprint()
    file_results = []
    for name, expected in manifest.get("files", {}).items():
        data = contents.get(name)
        actual = hashlib.sha256(data).hexdigest() if data is not None else None
        status = ("CORRUPTED" if name in corrupted else "missing") if data is None else \
            ("match" if actual == expected else "MODIFIED")
        file_results.append({"file": name, "ok": actual == expected, "status": status})
    files_ok = all(f["ok"] for f in file_results)
    return {"ok": sig_ok and files_ok and trusted_key, "signature_valid": sig_ok,
            "signed_by_this_installation": trusted_key, "files_ok": files_ok,
            "files": file_results, "alert_id": manifest.get("alert_id"),
            "exported_at": manifest.get("exported_at"), "exported_by": manifest.get("exported_by")}
