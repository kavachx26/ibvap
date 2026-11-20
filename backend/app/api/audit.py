"""Tamper-evidence: verification, chain explorer, checkpoints, live attack demo."""

from __future__ import annotations

import hashlib
import html
import json
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from app.config import APP_NAME, APP_VERSION, TEAM_NAME
from app.core import crypto, storage

router = APIRouter()


def _ts(t):
    return time.strftime("%d %b %Y, %H:%M:%S", time.localtime(t)) if t else "-"


def _val(v) -> str:
    s = json.dumps(v) if not isinstance(v, str) else v
    return html.escape(s if len(s) <= 160 else s[:157] + "...")


@router.get("/api/audit/report", response_class=HTMLResponse)
def integrity_report():
    """Printable chain-integrity report: the verdict of each tamper-evidence
    layer, the exact broken link, a field diff of every altered row, and the
    state of each signed checkpoint. Its verdict summary is itself signed
    with the installation's Ed25519 key."""
    v = storage.verify_all()
    e = html.escape
    chain, integ, cps = v["chain"], v["integrity"], v["checkpoints"]
    tampered_rows = (storage.row_tamper_details("alerts", integ["tampered_alert_ids"])
                     + storage.row_tamper_details("events", integ["tampered_event_ids"])
                     + storage.row_tamper_details("alert_actions", integ["tampered_action_ids"]))
    n_rows = len(integ["tampered_alert_ids"]) + len(integ["tampered_event_ids"]) + len(integ["tampered_action_ids"])
    brk = storage.chain_break_detail(chain["broken_at_id"]) if not chain["chain_intact"] else None
    cp_rows = storage.checkpoint_report()
    recent = storage.fetch_audit_records(15)
    now = time.time()

    summary = {
        "product": f"{APP_NAME} {APP_VERSION}", "generated_at": round(now, 3), "overall_ok": v["ok"],
        "hash_chain_intact": chain["chain_intact"], "broken_at_id": chain["broken_at_id"],
        "records_checked": chain["records_checked"], "head_hash": chain["head_hash"],
        "tampered_alert_ids": integ["tampered_alert_ids"], "tampered_event_ids": integ["tampered_event_ids"],
        "tampered_action_ids": integ["tampered_action_ids"],
        "checkpoints_ok": cps["ok"], "checkpoints_total": cps["total"],
        "failed_checkpoints": [f["checkpoint_id"] for f in cps["failed"]],
    }
    summary_json = json.dumps(summary, sort_keys=True)
    digest = hashlib.sha256(summary_json.encode()).hexdigest()
    signature = crypto.sign(summary_json.encode())

    ok = v["ok"]
    good, bad = "#137a4a", "#b42318"

    def layer(name, passed, detail, caught):
        col = good if passed else bad
        return (f"<tr><td><b>{name}</b></td><td><span class='pill' style='background:{col}'>"
                f"{'PASS' if passed else 'FAIL'}</span></td><td>{detail}</td><td class='muted'>{caught}</td></tr>")

    layers = "".join([
        layer("1. SHA-256 hash chain", chain["chain_intact"],
              f"{chain['records_checked']} linked records" + ("" if chain["chain_intact"]
                                                             else f"; first broken link at record #{chain['broken_at_id']}"),
              "a single record edited or deleted"),
        layer("2. Row snapshots", n_rows == 0,
              "every visible row matches its chained copy" if n_rows == 0 else f"{n_rows} row(s) differ from their chained copy",
              "the visible tables edited, chain untouched"),
        layer("3. Ed25519-signed checkpoints", cps["ok"],
              f"{cps['total']} signed checkpoints valid" if cps["ok"]
              else f"{len(cps['failed'])} of {cps['total']} checkpoints fail: {e(cps['failed'][0]['reason'])}",
              "the whole chain rewritten and re-hashed by an insider"),
    ])

    if ok:
        verdict = ("NO TAMPERING DETECTED. Every record is linked, every visible row matches its chained copy, "
                   "and the chain matches every signed checkpoint.")
    else:
        failed = [n for n, p in (("hash chain", chain["chain_intact"]), ("row snapshots", n_rows == 0),
                                 ("signed checkpoints", cps["ok"])) if not p]
        verdict = f"TAMPERING DETECTED by: {', '.join(failed)}. Do not rely on the affected records."
        if chain["chain_intact"] and n_rows == 0 and not cps["ok"]:
            verdict += (" The hash chain and row snapshots both pass, which means the chain was rewritten and "
                        "re-hashed consistently. Only the signed checkpoints, whose key is not in the database, expose it.")

    brk_html = ""
    if brk:
        brk_html = f"""<h2>Broken link</h2>
<p>{e(brk['reason'])}</p>
<table class="kv"><tr><td>Record</td><td>#{brk['audit_id']} ({e(brk['record_type'])})</td></tr>
<tr><td>Stored prev_hash</td><td class="mono bad">{e(brk['stored_prev_hash'])}</td></tr>
<tr><td>Expected prev_hash</td><td class="mono">{e(brk['expected_prev_hash'])}{' (hash of record #' + str(brk['previous_record_id']) + ')' if brk['previous_record_id'] else ' (genesis)'}</td></tr>
<tr><td>Stored hash</td><td class="mono">{e(brk['stored_hash'])}</td></tr>
<tr><td>Recomputed hash</td><td class="mono {'bad' if brk['recomputed_hash'] != brk['stored_hash'] else ''}">{e(brk['recomputed_hash'])}</td></tr>
<tr><td>Payload now</td><td class="mono">{_val(brk['payload'])}</td></tr></table>"""

    rows_html = ""
    if tampered_rows:
        body = ""
        for r in tampered_rows:
            for c in r["changes"] or [{"field": "-", "chained": "-", "live": "-"}]:
                body += (f"<tr><td>{e(r['table'])} #{r['id']}</td><td>#{r['audit_id']}</td><td>{e(c['field'])}</td>"
                         f"<td class='mono'>{_val(c['chained'])}</td><td class='mono bad'>{_val(c['live'])}</td></tr>")
        more = f"<p class='muted'>Showing the first 20 altered rows of {n_rows}.</p>" if n_rows > 20 else ""
        rows_html = f"""<h2>Altered rows</h2><p>The chained copy is what was recorded at detection time; the live value is what the table says now.</p>
<table><tr><th>Row</th><th>Audit record</th><th>Field</th><th>Chained (original)</th><th>Live (now)</th></tr>{body}</table>{more}"""

    cp_body = "".join(
        f"<tr><td>#{c['id']}</td><td>{_ts(c['created_at'])}</td><td>#{c['upto_audit_id']}</td>"
        f"<td class='mono'>{e(c['signed_head_hash'][:20])}...</td>"
        f"<td class='mono {'' if c['current_hash'] == c['signed_head_hash'] else 'bad'}'>{e((c['current_hash'] or 'deleted')[:20])}...</td>"
        f"<td>{c['signed_count']} / <span class='{'' if c['signed_count'] == c['current_count'] else 'bad'}'>{c['current_count']}</span></td>"
        f"<td>{'valid' if c['signature_valid'] else '<b class=bad>invalid</b>'}</td>"
        f"<td><span class='pill' style='background:{good if c['ok'] else bad}'>{'OK' if c['ok'] else 'FAIL'}</span></td></tr>"
        for c in cp_rows) or "<tr><td colspan=8 class='muted'>No checkpoints yet.</td></tr>"

    broken_id = chain["broken_at_id"]
    rec_body = "".join(
        f"<tr class='{'brk' if r['id'] == broken_id else ''}'><td>#{r['id']}</td><td>{e(r['record_type'])}</td>"
        f"<td>{_ts(r['timestamp'])}</td><td class='mono'>{e(r['prev_hash'][:16])}...</td><td class='mono'>{e(r['hash'][:16])}...</td></tr>"
        for r in recent)

    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Chain integrity report - {APP_NAME}</title>
<style>
 body{{font:13px/1.5 'Segoe UI',Arial,sans-serif;color:#101828;max-width:960px;margin:28px auto;padding:0 24px}}
 header{{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:3px solid #0b3b66;padding-bottom:8px}}
 h1{{font-size:22px;margin:0}} h2{{font-size:15px;color:#0b3b66;margin:22px 0 6px}}
 .sub,.muted{{color:#667085}} .mono{{font-family:Consolas,monospace;font-size:11px;word-break:break-all}}
 .verdict{{margin:16px 0;padding:14px 16px;border-radius:8px;font-weight:600;font-size:14px;
   border:1px solid {good if ok else bad};background:{good if ok else bad}12;color:{good if ok else bad}}}
 table{{width:100%;border-collapse:collapse;margin:6px 0}} td,th{{padding:6px 8px;border-bottom:1px solid #eaecf0;text-align:left;vertical-align:top}}
 th{{background:#f2f4f7;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#475467}}
 table.kv td:first-child{{width:170px;color:#475467;font-weight:600}}
 .pill{{display:inline-block;color:#fff;font-weight:700;font-size:11px;padding:2px 9px;border-radius:999px}}
 .bad{{color:{bad}}} tr.brk td{{background:#fef3f2}}
 .sig{{margin-top:22px;padding:10px 12px;border:1px dashed #d0d5dd;border-radius:8px;font-size:11px}}
 footer{{margin-top:18px;font-size:11px;color:#667085}}
 @media print{{body{{margin:0}} .noprint{{display:none}}}}
</style></head><body>
<header><div><h1>Chain Integrity Report</h1><div class="sub">{APP_NAME} - Intelligent Border Video Analytics Platform - tamper-evidence verification</div></div>
<div class="sub">Generated {_ts(now)}</div></header>
<div class="verdict">{e(verdict)}</div>
<h2>Verification layers</h2>
<table><tr><th style="width:24%">Layer</th><th style="width:8%">Result</th><th>Finding</th><th style="width:24%">Catches</th></tr>{layers}</table>
<table class="kv"><tr><td>Records checked</td><td>{chain['records_checked']}</td></tr>
<tr><td>Current chain head</td><td class="mono">{e(chain['head_hash'] or '(broken: no trusted head)')}</td></tr>
<tr><td>Signing key</td><td class="mono">Ed25519 {crypto.key_fingerprint()}</td></tr></table>
{brk_html}{rows_html}
<h2>Signed checkpoints (latest {len(cp_rows)})</h2>
<table><tr><th>ID</th><th>Signed at</th><th>Up to record</th><th>Signed head hash</th><th>Hash there now</th><th>Records signed / now</th><th>Signature</th><th>Status</th></tr>{cp_body}</table>
<h2>Latest chain records</h2>
<table><tr><th>Record</th><th>Type</th><th>Logged</th><th>prev_hash</th><th>hash</th></tr>{rec_body}</table>
<div class="sig"><b>This report is signed.</b> SHA-256 of the verdict summary: <span class="mono">{digest}</span><br>
Ed25519 signature: <span class="mono">{signature}</span><br>
<span class="muted">Summary signed: <span class="mono">{e(summary_json)}</span></span></div>
<footer>{APP_NAME} {APP_VERSION} - {TEAM_NAME}. Use the browser's Print, then Save as PDF, to file this report.
<span class="noprint">Public key: GET /api/audit/public-key.</span></footer>
</body></html>"""
    return HTMLResponse(page)


@router.get("/api/audit/verify")
def audit_verify():
    return storage.verify_all()


@router.get("/api/audit/records")
def audit_records(limit: int = 40, before_id: Optional[int] = None):
    return storage.fetch_audit_records(min(limit, 200), before_id)


@router.get("/api/audit/records/{audit_id}")
def audit_record(audit_id: int):
    r = storage.fetch_audit_record(audit_id)
    if r is None:
        raise HTTPException(404, "No such audit record")
    r["recomputed_hash"] = storage.compute_hash(r["prev_hash"], r["record_type"], r["payload"], r["timestamp"])
    r["self_consistent"] = r["recomputed_hash"] == r["hash"]
    return r


@router.get("/api/audit/checkpoints")
def checkpoints(limit: int = 20):
    return {"checkpoints": storage.fetch_checkpoints(limit), "key_fingerprint": crypto.key_fingerprint()}


@router.post("/api/audit/checkpoint")
def make_checkpoint():
    cp = storage.create_checkpoint()
    if cp is None:
        raise HTTPException(400, "Audit log is empty")
    return cp


@router.get("/api/audit/public-key")
def public_key():
    return {"algorithm": "Ed25519", "fingerprint": crypto.key_fingerprint(), "pem": crypto.public_key_pem()}


@router.post("/api/audit/demo/seed")
def demo_seed():
    return storage.seed_tamper_demo()


@router.post("/api/audit/demo/attack1")
def demo_attack1():
    return storage.simulate_visible_edit_attack()


@router.post("/api/audit/demo/attack2")
def demo_attack2():
    return storage.simulate_chain_rewrite_attack()


@router.post("/api/audit/demo/attack3")
def demo_attack3():
    return storage.simulate_full_chain_forgery()


@router.post("/api/data/reset")
def data_reset():
    return storage.reset_all_data()
