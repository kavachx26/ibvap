// IBVAP command center (vanilla ES modules, no build step, works offline).
import { api, authenticate, link, LiveSocket, session, tryKey } from './api.js';
import { hBars, hideTip, lineChart, paintHeat, stackedColumns } from './charts.js';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const SEV_COLOR = { low: 'var(--s-low)', medium: 'var(--s-warn)', high: 'var(--s-serious)', critical: 'var(--s-crit)' };
const TYPE_LABEL = {
  watchlist_match: 'Watchlist match', unauthorized_crossing: 'Unauthorized crossing', loitering: 'Loitering',
  group_formation: 'Group / convoy', erratic_motion: 'Erratic motion', night_time_movement: 'Night movement',
};
const STATUS_LABEL = { new: 'New', acknowledged: 'Acknowledged', investigating: 'Investigating', escalated: 'Escalated', resolved: 'Resolved', false_positive: 'False positive' };

const S = {
  cameras: [], camById: {}, threat: { cameras: {}, site: { level: 'LOW', score: 0 } },
  view: 'command', mainCam: 'cam-01', mainStream: null, wallStreams: [], replayStream: null,
  streamAlerts: [], sevFilter: 'all', sound: false, lastFrame: {}, verify: null, rangeMin: 60,
  selectedPlate: null, calib: { mode: 'line', pts: [], geom: null, frameW: 960, frameH: 540 },
};

const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-');
const fmtAgo = (t) => {
  const d = Math.max(0, Date.now() / 1000 - t);
  if (d < 60) return `${Math.round(d)}s ago`;
  if (d < 3600) return `${Math.round(d / 60)}m ago`;
  return `${Math.round(d / 3600)}h ago`;
};
const camName = (id) => S.camById[id]?.name || id;
const sevBadge = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const statusBadge = (s) => `<span class="status ${esc(s)}">${esc(STATUS_LABEL[s] || s)}</span>`;

// ------------------------------------------------------------------ toasts / sound
function toast(title, body = '', kind = '', onClick) {
  const t = document.createElement('div');
  t.className = `toast ${kind}`;
  t.innerHTML = `<div class="t">${esc(title)}</div><div class="muted small">${esc(body)}</div>`;
  if (onClick) t.addEventListener('click', () => { onClick(); t.remove(); });
  $('#toasts').prepend(t);
  setTimeout(() => t.remove(), kind === 'critical' ? 9000 : 4500);
  while ($('#toasts').children.length > 3) $('#toasts').lastChild.remove();
}
let audioCtx;
function beep(freq = 880, dur = 0.14) {
  if (!S.sound) return;
  try {
    audioCtx = audioCtx || new AudioContext();
    const o = audioCtx.createOscillator(), g = audioCtx.createGain();
    o.frequency.value = freq; o.type = 'square'; g.gain.value = 0.04;
    o.connect(g); g.connect(audioCtx.destination); o.start(); o.stop(audioCtx.currentTime + dur);
  } catch { /* audio blocked */ }
}

// ------------------------------------------------------------------ stream viewer
class StreamView {
  constructor(streamId, img, { onFrame, onState, emptyEl } = {}) {
    this.img = img; this.onFrame = onFrame; this.emptyEl = emptyEl;
    this.sock = new LiveSocket(`/api/ws/stream/${encodeURIComponent(streamId)}`, (m) => this.handle(m), onState);
  }
  handle(m) {
    if (m.type === 'frame') {
      if (m.jpeg_b64) this.img.src = 'data:image/jpeg;base64,' + m.jpeg_b64;
      if (this.emptyEl) this.emptyEl.style.display = 'none';
      this.onFrame?.(m);
    } else if (m.type === 'done' || m.type === 'error') this.onFrame?.(m);
  }
  close() { this.sock.close(); }
}

// ------------------------------------------------------------------ router
const VIEWS = {
  command: { enter: enterCommand, leave: () => {} },
  wall: { enter: enterWall, leave: leaveWall },
  incidents: { enter: loadIncidents },
  intel: { enter: enterIntel },
  analytics: { enter: loadAnalytics },
  audit: { enter: enterAudit },
  sources: { enter: loadSamples },
  system: { enter: enterSystem, leave: () => {} },
};
function showView(name) {
  if (!VIEWS[name]) name = 'command';
  if (S.view !== name) VIEWS[S.view]?.leave?.();
  S.view = name;
  $$('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.view === name));
  $('#sidebar').classList.remove('open');
  hideTip();
  VIEWS[name].enter?.();
}
window.addEventListener('hashchange', () => showView(location.hash.slice(1)));

// ------------------------------------------------------------------ event bus
function connectBus() {
  new LiveSocket('/api/ws/events', onBus, (st) => {
    $('#connDot').className = 'dot' + (st === 'open' ? ' live' : '');
    $('#connText').textContent = st === 'open' ? 'Live' : 'Reconnecting';
  });
}
function onBus(m) {
  if (m.type === 'alert') onAlert(m.alert);
  else if (m.type === 'threat') onThreat(m);
}
function onAlert(a) {
  S.streamAlerts.unshift(a);
  S.streamAlerts.length = Math.min(S.streamAlerts.length, 120);
  renderStream();
  const watched = S.view === 'command' && a.camera_id === S.mainCam;
  if (a.alert_type === 'watchlist_match' || (a.severity === 'critical' && watched)) {
    // Watchlist hits always interrupt; other critical alerts only for the camera on screen.
    beep(a.alert_type === 'watchlist_match' ? 1180 : 880);
    toast(`${TYPE_LABEL[a.alert_type] || a.alert_type}: ${camName(a.camera_id)}`, a.message, 'critical', () => openIncident(a.id));
  }
  if (a.severity === 'critical' && watched) { const f = $('#feedFlash'); f.classList.remove('go'); void f.offsetWidth; f.classList.add('go'); }
  if (S.view === 'incidents') debounce('inc', loadIncidents, 1500);
  if (S.view === 'intel' && a.alert_type === 'watchlist_match') debounce('intel', loadIntelLists, 1500);
  debounce('kpi', loadKpis, 1200);
  const cell = $(`.wall-cell[data-cam="${a.camera_id}"] .last`);
  if (cell) cell.textContent = `${fmtTime(a.created_at)}  ${a.message}`;
}
function onThreat(m) {
  S.threat = m;
  const site = m.site || { level: 'LOW', score: 0 };
  $('#sitePill').dataset.level = site.level;
  $('#siteLevel').textContent = site.level;
  $('#siteScore').textContent = Math.round(site.score);
  renderSectors(); renderCamTabs();
  $$('.wall-cell').forEach((c) => {
    const t = m.cameras?.[c.dataset.cam];
    if (t) { c.dataset.level = t.level; $('.lvlt', c).textContent = `${t.level} ${Math.round(t.score)}`; }
  });
}
const _deb = {};
function debounce(k, fn, ms) { clearTimeout(_deb[k]); _deb[k] = setTimeout(fn, ms); }

// ------------------------------------------------------------------ command center
async function loadCameras() {
  S.cameras = await api('/api/cameras');
  S.camById = Object.fromEntries(S.cameras.map((c) => [c.id, c]));
  const opts = S.cameras.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
  $('#fCam').insertAdjacentHTML('beforeend', opts);
  $('#occCam').innerHTML = opts; $('#calCam').innerHTML = opts;
}
function renderCamTabs() {
  $('#camTabs').innerHTML = S.cameras.map((c) => {
    const t = S.threat.cameras?.[c.id];
    return `<button class="cam-tab ${c.id === S.mainCam ? 'on' : ''}" data-cam="${c.id}" data-level="${t?.level || 'LOW'}" type="button" title="${esc(c.post)}"><span class="lv"></span>${esc(c.name.split(' - ')[0])}</button>`;
  }).join('');
}
function renderSectors() {
  $('#sectorList').innerHTML = S.cameras.map((c) => {
    const t = S.threat.cameras?.[c.id] || { level: 'LOW', score: 0, recent_open_alerts: 0 };
    return `<div class="sector" data-cam="${c.id}" data-level="${t.level}" title="${t.recent_open_alerts} open alerts in window">
      <span class="nm">${esc(c.name)}</span><span class="lvlt">${t.level} &middot; ${Math.round(t.score)}</span>
      <div class="meter"><i style="width:${Math.max(2, t.score)}%"></i></div></div>`;
  }).join('');
}
function setMainCam(id) {
  S.mainCam = id;
  renderCamTabs();
  S.mainStream?.close();
  $('#feedEmpty').style.display = '';
  $('#trackList').innerHTML = '';
  S.mainStream = new StreamView(id, $('#feedImg'), { onFrame: onMainFrame, emptyEl: $('#feedEmpty') });
  if ($('#tglHeat').checked) refreshHeat();
}
function onMainFrame(m) {
  if (m.type !== 'frame') return;
  S.lastFrame[m.camera_id] = m;
  const night = m.night_mode ? '<span style="color:#c39bff">IR / low-light enhanced</span>' : '';
  $('#feedMeta').innerHTML = `<span>Persons <b>${m.people_count}</b></span><span>Vehicles <b>${m.vehicle_count}</b></span>
    <span>Pipeline <b>${m.step_ms} ms</b></span><span>Stream <b>${m.fps || '-'} fps</b></span><span>Frame <b>${m.frame_index}</b></span>${night}`;
  $('#trackList').innerHTML = m.tracks.slice(0, 14).map((t) => {
    const watch = t.plate && S.watchPlates?.has(t.plate);
    return `<span class="trk ${t.label === 'person' ? 'p' : 'v'} ${watch ? 'w' : ''}">${t.label === 'person' ? 'P' : t.label.slice(0, 3).toUpperCase()}-${t.id}${t.plate ? ' ' + esc(t.plate) : ''}</span>`;
  }).join('');
}
async function refreshHeat() {
  if (!$('#tglHeat').checked || S.view !== 'command') return;
  try {
    const h = await api(`/api/streams/${S.mainCam}/heatmap`);
    paintHeat($('#heatCanvas'), h.grid, h.w, h.h);
  } catch { /* session not ready yet */ }
}
function renderStream() {
  const list = S.streamAlerts.filter((a) => S.sevFilter === 'all' || (S.sevFilter === 'critical' ? a.severity === 'critical' : SEV_RANK[a.severity] >= 2));
  $('#streamCount').textContent = S.streamAlerts.length ? `(${S.streamAlerts.length})` : '';
  if (!list.length) { $('#alertStream').innerHTML = '<div class="empty">Alerts from every camera appear here in real time.</div>'; return; }
  $('#alertStream').innerHTML = list.slice(0, 40).map((a) => `
    <div class="ac ${a.severity} ${a.status && a.status !== 'new' ? 'acked' : ''}" data-id="${a.id}">
      <div class="bar"></div>
      <div><div class="top">${sevBadge(a.severity)}<span class="muted small">${fmtTime(a.created_at)}</span></div>
      <div class="msg">${a.plate ? `<span class="plate watch">${esc(a.plate)}</span> ` : ''}${esc(a.message)}</div>
      <div class="meta"><span>${esc(camName(a.camera_id))}</span><span>#${a.id}</span><span>${esc(TYPE_LABEL[a.alert_type] || a.alert_type)}</span></div></div>
    </div>`).join('');
}
async function loadKpis() {
  try {
    const [h, all, v] = await Promise.all([api('/api/analytics/summary?since_minutes=60'), api('/api/analytics/summary'),
      S.verify ? Promise.resolve(S.verify) : api('/api/audit/verify')]);
    S.verify = v;
    const crit = h.by_severity.critical || 0;
    const tiles = [
      ['Alerts (1 h)', h.total_alerts, `${all.total_alerts} all time`, ''],
      ['Critical (1 h)', crit, `${h.by_severity.high || 0} high`, crit ? 'alarm' : ''],
      ['Open incidents', all.open_alerts, `${(all.by_status.escalated || 0)} escalated`, ''],
      ['Plates read', all.unique_plates, 'unique, all cameras', ''],
      ['Watchlist hits', all.watchlist_hits, 'OCR-tolerant matching', all.watchlist_hits ? 'alarm' : ''],
      ['Evidence chain', v.ok ? 'Verified' : 'TAMPERED', `${v.chain.records_checked} records, ${v.checkpoints.total} signed`, v.ok ? 'okk' : 'alarm'],
    ];
    const host = $('#kpis');
    const prev = host.dataset.sig;
    host.innerHTML = tiles.map(([k, val, d, cls]) => `<div class="kpi ${cls}"><div class="k">${k}</div><div class="v">${val}</div><div class="d">${d}</div></div>`).join('');
    host.dataset.sig = JSON.stringify(tiles.map((t) => t[1]));
    if (prev && prev !== host.dataset.sig) $$('.kpi', host).forEach((k) => k.classList.add('bump'));
    const nb = $('#navOpen'); nb.textContent = all.open_alerts > 999 ? '999+' : all.open_alerts; nb.toggleAttribute('data-zero', !all.open_alerts);
    setChainChip(v);
  } catch (e) { console.warn(e); }
}
function setChainChip(v) {
  const c = $('#chainChip');
  c.className = 'chip ' + (v.ok ? 'ok' : 'bad');
  $('#chainText').textContent = v.ok ? `Chain verified (${v.chain.records_checked})` : 'Chain TAMPERED';
}
async function refreshVerify() { try { S.verify = await api('/api/audit/verify'); setChainChip(S.verify); } catch { /* offline */ } }
function enterCommand() {
  if (!S.mainStream) setMainCam(S.mainCam);
  loadKpis();
}

// ------------------------------------------------------------------ wall
function enterWall() {
  leaveWall();
  $('#wall').innerHTML = S.cameras.map((c) => {
    const t = S.threat.cameras?.[c.id] || { level: 'LOW', score: 0 };
    return `<div class="wall-cell" data-cam="${c.id}" data-level="${t.level}">
      <div class="wall-head"><div><b>${esc(c.name)}</b> <span class="muted small">${esc(c.post)}</span></div><span class="lvlt">${t.level} ${Math.round(t.score)}</span></div>
      <div class="feed"><img alt="${esc(c.name)}"><div class="feed-empty"><div class="spinner"></div></div></div>
      <div class="wall-foot"><span class="last muted">No alerts yet</span><span class="stats"></span></div></div>`;
  }).join('');
  S.wallStreams = $$('.wall-cell').map((cell) => new StreamView(cell.dataset.cam, $('img', cell), {
    emptyEl: $('.feed-empty', cell),
    onFrame: (m) => { if (m.type === 'frame') $('.stats', cell).textContent = `P ${m.people_count} · V ${m.vehicle_count}${m.night_mode ? ' · IR' : ''}`; },
  }));
  $$('.wall-cell').forEach((cell) => cell.addEventListener('dblclick', () => { setMainCam(cell.dataset.cam); location.hash = 'command'; }));
}
function leaveWall() { S.wallStreams.forEach((s) => s.close()); S.wallStreams = []; }

// ------------------------------------------------------------------ incidents
async function loadIncidents() {
  const p = new URLSearchParams({ limit: 300 });
  for (const [id, key] of [['#fSev', 'severity'], ['#fStatus', 'status'], ['#fCam', 'camera_id'], ['#fType', 'alert_type'], ['#fQ', 'q']]) {
    const v = $(id).value.trim(); if (v) p.set(key, v);
  }
  const rows = await api('/api/alerts?' + p);
  $('#incCount').textContent = `${rows.length} shown`;
  $('#incAll').checked = false;
  $('#incTable tbody').innerHTML = rows.length ? rows.map((a) => `
    <tr data-id="${a.id}"><td class="cb"><input type="checkbox" value="${a.id}" aria-label="Select"></td>
    <td class="mono">#${a.id}</td><td>${sevBadge(a.severity)}</td><td>${esc(TYPE_LABEL[a.alert_type] || a.alert_type)}</td>
    <td class="msg">${a.plate ? `<span class="plate watch">${esc(a.plate)}</span> ` : ''}${esc(a.message)}</td>
    <td>${esc(camName(a.camera_id))}</td><td class="mono">${fmtTime(a.created_at)}</td><td>${statusBadge(a.status)}</td>
    <td>${a.snapshot_hash ? '<span class="muted small" title="Evidence frame captured">frame</span>' : ''}</td></tr>`).join('')
    : '<tr><td colspan="9"><div class="empty">No incidents match these filters.</div></td></tr>';
}

// ------------------------------------------------------------------ incident drawer
async function openIncident(id) {
  const d = await api(`/api/alerts/${id}`);
  const a = d.alert;
  $('#dwKicker').innerHTML = `Incident #${a.id} &middot; ${esc(camName(a.camera_id))}`;
  $('#dwTitle').textContent = TYPE_LABEL[a.alert_type] || a.alert_type;
  const img = a.snapshot_hash
    ? `<div class="evidence"><img src="${link(`/api/alerts/${a.id}/snapshot`)}" alt="Evidence frame"><span class="seal chip ${d.row_intact ? 'ok' : 'bad'}">${d.row_intact ? 'SHA-256 matches chained record' : 'Record altered'}</span></div>`
    : '<div class="empty">No evidence frame for this alert.</div>';
  const wf = [['acknowledged', 'Acknowledge'], ['investigating', 'Investigate'], ['escalated', 'Escalate'], ['resolved', 'Resolve'], ['false_positive', 'False positive']];
  $('#dwBody').innerHTML = `
    ${img}
    <div class="wf">${sevBadge(a.severity)} ${statusBadge(a.status)} ${a.assignee ? `<span class="chip">Owner: ${esc(a.assignee)}</span>` : ''}</div>
    <div>${a.plate ? `<span class="plate watch">${esc(a.plate)}</span> ` : ''}${esc(a.message)}</div>
    <dl class="kv">
      <dt>Camera</dt><dd>${esc(camName(a.camera_id))} <span class="muted">${esc(d.camera?.post || '')}</span></dd>
      <dt>Detected</dt><dd>${new Date(a.created_at * 1000).toLocaleString()} <span class="muted">(stream t+${a.timestamp.toFixed(1)}s)</span></dd>
      <dt>Track IDs</dt><dd class="mono">${esc(a.track_ids)}</dd>
      <dt>Evidence hash</dt><dd class="mono">${esc(a.snapshot_hash || '-')}</dd>
      <dt>Audit record</dt><dd class="mono">#${a.audit_id} &middot; ${esc((d.audit_record?.hash || '').slice(0, 24))}&hellip;</dd>
    </dl>
    <div><div class="section-t">Workflow</div>
      <div class="wf">${wf.map(([k, l]) => `<button class="btn btn-sm ${k === 'escalated' ? 'btn-danger' : 'btn-ghost'}" data-act="${k}" type="button" ${a.status === k ? 'disabled' : ''}>${l}</button>`).join('')}</div>
      <div class="note-row" style="margin-top:8px"><input id="dwNote" placeholder="Add a note to the custody trail" maxlength="300"><button class="btn btn-sm btn-ghost" data-act="note" type="button">Add note</button></div></div>
    <div><div class="section-t">Chain of custody</div>
      <ol class="custody"><li><b>Alert raised</b> by IBVAP pipeline<div class="when">${new Date(a.created_at * 1000).toLocaleString()}</div></li>
      ${d.actions.map((x) => `<li><b>${esc(STATUS_LABEL[x.action] || (x.action === 'note' ? 'Note' : x.action))}</b> by ${esc(x.operator)}${x.note ? `: <span class="muted">${esc(x.note)}</span>` : ''}<div class="when">${new Date(x.created_at * 1000).toLocaleString()}</div></li>`).join('')}</ol></div>
    <div class="wf"><a class="btn btn-ghost" href="${link(`/api/alerts/${a.id}/report`)}" target="_blank" rel="noopener"><svg><use href="#i-doc"/></svg>Incident report</a>
      <button class="btn btn-accent" id="dwBundle" type="button"><svg><use href="#i-download"/></svg>Signed evidence bundle</button></div>`;
  $$('[data-act]', $('#dwBody')).forEach((b) => b.addEventListener('click', async () => {
    const action = b.dataset.act;
    const note = $('#dwNote').value.trim() || null;
    if (action === 'note' && !note) { $('#dwNote').focus(); return; }
    await api(`/api/alerts/${a.id}/action`, { method: 'POST', body: { action, note } });
    toast('Recorded in custody trail', `${STATUS_LABEL[action] || 'Note'} by ${session.operator}`, 'ok');
    const sa = S.streamAlerts.find((x) => x.id === a.id); if (sa && action !== 'note') sa.status = action;
    renderStream(); openIncident(a.id); if (S.view === 'incidents') loadIncidents(); loadKpis();
  }));
  $('#dwBundle').addEventListener('click', () => downloadBundle(a.id));
  $('#drawer').classList.add('on'); $('#scrim').classList.add('on'); $('#drawer').setAttribute('aria-hidden', 'false');
}
function closeDrawer() { $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on'); $('#drawer').setAttribute('aria-hidden', 'true'); }
async function downloadBundle(id) {
  const res = await api(`/api/alerts/${id}/evidence`, { raw: true });
  const blob = await res.blob();
  const u = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: u, download: `IBVAP_evidence_alert_${id}.zip` });
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 2000);
  toast('Signed evidence bundle exported', 'Ed25519-signed manifest + SHA-256 of every file', 'ok');
}

// ------------------------------------------------------------------ vehicle intel
async function enterIntel() { await loadIntelLists(); drawSiteMap(); if (S.selectedPlate) showTrajectory(S.selectedPlate); }
async function loadIntelLists() {
  const [plates, wl] = await Promise.all([api('/api/intel/plates?' + new URLSearchParams({ q: $('#plateQ').value.trim() })), api('/api/intel/watchlist')]);
  S.watchPlates = new Set(wl.map((w) => w.plate));
  $('#plateList').innerHTML = plates.length ? plates.map((p) => `
    <div class="pl ${p.plate === S.selectedPlate ? 'on' : ''}" data-plate="${esc(p.plate)}">
      <span class="plate ${p.watchlist_plate ? 'watch' : ''}">${esc(p.plate)}</span>
      <span class="small">${p.watchlist_plate ? '<span class="sev critical">watchlist</span>' : (p.format_valid ? '' : '<span class="muted">unverified format</span>')}</span>
      <span class="mono small">${p.sightings}x</span>
      <span class="sub">${p.cameras} camera${p.cameras > 1 ? 's' : ''} &middot; last ${fmtAgo(p.last_seen)} &middot; ${esc(p.source)}</span></div>`).join('')
    : '<div class="empty">No plates read yet. Open the Check Post camera.</div>';
  $('#wlCount').textContent = `${wl.length} vehicles`;
  $('#wlList').innerHTML = wl.map((w) => `
    <div class="wl"><span><span class="plate watch">${esc(w.plate)}</span> <span class="sev ${w.priority === 'critical' ? 'critical' : 'high'}">${esc(w.priority)}</span></span>
    <button class="icon-btn" data-del="${esc(w.plate)}" title="Remove" type="button"><svg><use href="#i-x"/></svg></button>
    <span class="r">${esc(w.reason)}</span>
    <span class="h">${w.hits ? `<b style="color:var(--s-crit)">${w.hits} sighting${w.hits > 1 ? 's' : ''}</b>, last ${fmtAgo(w.last_seen)} at ${esc(camName(w.last_camera))}` : 'Not sighted'} &middot; added by ${esc(w.added_by)}</span></div>`).join('');
}
function drawSiteMap(traj) {
  const svg = $('#siteMap');
  const hits = new Set(traj ? traj.sightings.map((s) => s.camera_id) : []);
  let html = `<defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,0L10,5L0,10z" fill="${traj?.watchlist ? 'var(--s-crit)' : 'var(--blue)'}"/></marker></defs>
    <rect x="1" y="1" width="98" height="68" rx="3" fill="none" stroke="var(--line)" stroke-width=".4"/>
    <path d="M2 50 C 25 46, 40 58, 60 52 S 90 46, 98 50" fill="none" stroke="var(--blue)" stroke-opacity=".35" stroke-width="3"/>
    <text x="4" y="66" style="font-size:2.3px;fill:var(--muted)">Schematic site layout (not to scale)</text>
    <path d="M50 2 V 46" stroke="var(--s-crit)" stroke-opacity=".35" stroke-width=".5" stroke-dasharray="1.5 1"/>
    <text x="51" y="6" style="font-size:2.2px;fill:var(--muted)">International border</text>`;
  if (traj) {
    const pts = []; let last;
    traj.sightings.forEach((s) => { if (s.camera_id !== last && s.map_x != null) { pts.push([s.map_x, s.map_y * 0.7]); last = s.camera_id; } });
    for (let i = 1; i < pts.length; i++) {
      const [x1, y1] = pts[i - 1], [x2, y2] = pts[i];
      const mx = (x1 + x2) / 2 + (y2 - y1) * 0.15, my = (y1 + y2) / 2 - (x2 - x1) * 0.15;
      html += `<path class="path ${traj.watchlist ? '' : 'normal'}" d="M${x1},${y1} Q${mx},${my} ${x2},${y2}" marker-end="url(#arr)"/>`;
    }
  }
  html += S.cameras.map((c) => {
    const x = c.map_x, y = c.map_y * 0.7;
    const t = S.threat.cameras?.[c.id];
    return `<g class="cam ${hits.has(c.id) ? 'hit' : ''}" data-level="${t?.level || 'LOW'}"><circle class="base" cx="${x}" cy="${y}" r="4.2"/>
      <circle cx="${x}" cy="${y}" r="1.5" fill="var(--lvl)"/><text x="${x}" y="${y + 7.5}" text-anchor="middle">${esc(c.name.split(' - ')[0])}</text></g>`;
  }).join('');
  svg.innerHTML = html;
}
async function showTrajectory(plate) {
  S.selectedPlate = plate;
  $$('.pl').forEach((p) => p.classList.toggle('on', p.dataset.plate === plate));
  try {
    const t = await api(`/api/intel/plates/${encodeURIComponent(plate)}/trajectory`);
    $('#trajTitle').innerHTML = `Trajectory <span class="plate ${t.watchlist ? 'watch' : ''}">${esc(t.plate)}</span>`;
    $('#trajMeta').textContent = `${t.total_sightings} sightings across ${t.cameras.length} camera(s), first ${fmtTime(t.first_seen)}, last ${fmtTime(t.last_seen)}`;
    drawSiteMap(t);
    const legByTo = {};
    t.legs.forEach((l) => { legByTo[l.to] = l; });
    let lastCam;
    $('#trajTimeline').innerHTML = (t.watchlist ? `<li style="border-color:var(--s-crit)"><span class="n" style="background:var(--crit-soft);color:var(--s-crit)">!</span><span><b>Watchlisted:</b> ${esc(t.watchlist.reason)}</span><span class="sev ${t.watchlist.priority === 'critical' ? 'critical' : 'high'}">${esc(t.watchlist.priority)}</span></li>` : '')
      + t.sightings.slice(-30).map((s, i) => {
        const moved = lastCam && s.camera_id !== lastCam; lastCam = s.camera_id;
        return `<li><span class="n">${i + 1}</span><span><b>${esc(s.camera_name)}</b>${moved ? ' <span class="muted small">(moved)</span>' : ''}<br><span class="muted small">track #${s.track_id} &middot; ${esc(s.source)}${s.match_type ? ` &middot; ${esc(s.match_type)} match` : ''}${s.raw_text && s.raw_text !== s.plate ? ` &middot; read "${esc(s.raw_text)}"` : ''}</span></span><span class="mono small">${fmtTime(s.created_at)}</span></li>`;
      }).join('');
  } catch (e) { $('#trajMeta').textContent = e.message; }
}

// ------------------------------------------------------------------ analytics
async function loadAnalytics() {
  const min = S.rangeMin, bucket = min <= 15 ? 30 : min <= 60 ? 120 : 900;
  const [tl, sum] = await Promise.all([api(`/api/analytics/timeline?minutes=${min}&bucket=${bucket}`), api(`/api/analytics/summary?since_minutes=${min}`)]);
  const keys = [{ key: 'low', label: 'Low', color: 'var(--s-low)' }, { key: 'medium', label: 'Medium', color: 'var(--s-warn)' },
    { key: 'high', label: 'High', color: 'var(--s-serious)' }, { key: 'critical', label: 'Critical', color: 'var(--s-crit)' }];
  $('#tlLegend').innerHTML = keys.map((k) => `<span><i style="background:${k.color}"></i>${k.label}</span>`).join('');
  stackedColumns($('#chTimeline'), tl.buckets, keys, { fmtX: (t) => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
  hBars($('#chTypes'), Object.entries(sum.by_type).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: TYPE_LABEL[k] || k, value: v, key: k })),
    { onClick: (d) => { $('#fType').value = d.key; location.hash = 'incidents'; } });
  hBars($('#chCams'), S.cameras.map((c) => ({ label: c.name.split(' - ')[0], title: c.name, value: sum.by_camera[c.id] || 0, key: c.id })),
    { onClick: (d) => { $('#fCam').value = d.key; location.hash = 'incidents'; } });
  hBars($('#chStatus'), Object.keys(STATUS_LABEL).map((k) => ({ label: STATUS_LABEL[k], value: sum.by_status[k] || 0 })), { color: 'var(--seq-3)' });
  loadOccupancy();
}
async function loadOccupancy() {
  const cam = $('#occCam').value || 'cam-01';
  $('#occCamName').textContent = camName(cam).split(' - ')[0];
  const rows = await api(`/api/analytics/occupancy/${cam}?minutes=10`);
  const people = rows.map((r) => ({ x: r.created_at, y: Math.max(0, r.people_count - r.vehicle_count) }));
  const veh = rows.map((r) => ({ x: r.created_at, y: r.vehicle_count }));
  lineChart($('#chOcc'), [{ name: 'Persons', color: 'var(--blue)', points: people }, { name: 'Vehicles', color: '#eb6834', points: veh }],
    { fmtX: (t) => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) });
}

// ------------------------------------------------------------------ audit
function renderVerify(v, flip) {
  const ok = (b) => (b ? 'ok' : 'bad');
  const ic = (b) => `<svg><use href="#${b ? 'i-check' : 'i-alert'}"/></svg>`;
  const tampered = v.integrity.tampered_alert_ids.length + v.integrity.tampered_event_ids.length + v.integrity.tampered_action_ids.length;
  const cards = [
    ['Overall', v.ok, v.ok ? 'Verified' : 'Tampering detected', `checked ${new Date(v.verified_at * 1000).toLocaleTimeString()}`],
    ['Hash chain', v.chain.chain_intact, v.chain.chain_intact ? 'Intact' : 'Broken', v.chain.chain_intact ? `${v.chain.records_checked} linked records` : `broken at record #${v.chain.broken_at_id}`],
    ['Row snapshots', !tampered, tampered ? `${tampered} altered` : 'Match', tampered ? `alerts ${v.integrity.tampered_alert_ids.join(', ') || '-'}` : 'tables match their chained snapshots'],
    ['Signed checkpoints', v.checkpoints.ok, v.checkpoints.ok ? 'Valid' : 'FAILED', v.checkpoints.ok ? `${v.checkpoints.total} Ed25519 signatures` : esc(v.checkpoints.failed[0]?.reason || '')],
  ];
  $('#verifyCards').innerHTML = cards.map(([k, good, val, d]) => `<div class="vc ${ok(good)} ${flip ? 'flip' : ''}"><div class="k">${k}</div><div class="v">${ic(good)}${val}</div><div class="d">${d}</div></div>`).join('');
}
async function enterAudit() {
  const v = await api('/api/audit/verify'); S.verify = v; setChainChip(v); renderVerify(v);
  loadChain();
  const k = await api('/api/audit/public-key');
  $('#keyBox').innerHTML = `<b>Installation signing key</b><br>Ed25519 &middot; fingerprint <code>${esc(k.fingerprint)}</code><br><span class="muted">Bundles signed by any other key are reported as untrusted.</span>`;
}
async function loadChain() {
  const [recs, cps, v] = await Promise.all([api('/api/audit/records?limit=24'), api('/api/audit/checkpoints?limit=50'), Promise.resolve(S.verify)]);
  const cpIds = new Set(cps.checkpoints.map((c) => c.upto_audit_id));
  const broken = v && !v.chain.chain_intact ? v.chain.broken_at_id : null;
  $('#chain').innerHTML = recs.map((r) => {
    let p = ''; try { const o = JSON.parse(r.payload); p = o.message || o.details || o.action || o.plate || ''; } catch { /* raw */ }
    return `<div class="blk ${cpIds.has(r.id) ? 'cp' : ''} ${broken === r.id ? 'broken' : ''}" title="prev ${esc(r.prev_hash)}">
      <div class="t"><span>#${r.id}</span><span class="muted">${esc(r.record_type)}</span></div>
      <div class="h">${esc(r.hash.slice(0, 20))}&hellip;</div><div class="h muted">prev ${esc(r.prev_hash.slice(0, 14))}&hellip;</div>
      <div class="p">${esc(p)}</div>${cpIds.has(r.id) ? '<div class="small" style="color:var(--accent);margin-top:4px">signed checkpoint</div>' : ''}</div>`;
  }).join('') || '<div class="empty">Audit log is empty.</div>';
}
async function runAttack(kind) {
  const logEl = $('#attackLog');
  const steps = $$('.attack');
  if (kind === 'seed') steps.forEach((s) => s.classList.remove('caught', 'missed'));
  const r = await api(`/api/audit/demo/${kind}`, { method: 'POST' });
  if (r.error) { logEl.textContent = r.error; return; }
  const v = await api('/api/audit/verify'); S.verify = v; setChainChip(v); renderVerify(v, true); loadChain(); loadKpis();
  const lines = [];
  if (kind === 'seed') lines.push(`Seeded ${r.seeded_alerts.length} alerts and ${r.seeded_events.length} events; signed checkpoint at record #${r.checkpoint?.upto_audit_id}.`, `Verification: ${v.ok ? 'VERIFIED' : 'FAILED'}`);
  else {
    lines.push(`Attack: ${r.attack.replaceAll('_', ' ')}`);
    if (r.before) lines.push(`  before: ${JSON.stringify(r.before.message ? { message: r.before.message, severity: r.before.severity } : r.before)}`);
    if (r.after) lines.push(`  after:  ${JSON.stringify({ message: r.after.message, severity: r.after.severity })}`);
    if (r.records_recomputed) lines.push(`  recomputed ${r.records_recomputed} hashes so the chain looks valid`);
    lines.push('', `Hash chain:        ${v.chain.chain_intact ? 'intact' + (kind === 'attack3' ? '  (fooled)' : '') : 'BROKEN at #' + v.chain.broken_at_id}`);
    lines.push(`Row snapshots:     ${v.integrity.tampered_alert_ids.length ? 'MISMATCH on alert ' + v.integrity.tampered_alert_ids.join(',') : 'match' + (kind === 'attack3' ? '  (fooled)' : '')}`);
    lines.push(`Signed checkpoint: ${v.checkpoints.ok ? 'valid' : 'FAILED: ' + v.checkpoints.failed[0].reason}`);
    lines.push('', v.ok ? 'RESULT: not detected' : `RESULT: DETECTED by ${r.caught_by}`);
    if (!v.ok) lines.push('Open "Integrity report" (top right) for the exact broken link and altered fields.');
    const idx = { attack1: 1, attack2: 2, attack3: 3 }[kind];
    steps[idx]?.classList.add(v.ok ? 'missed' : 'caught');
    toast(v.ok ? 'Attack not detected' : 'Tampering detected', r.caught_by, v.ok ? 'critical' : 'ok');
  }
  logEl.textContent = lines.join('\n');
}
async function verifyBundleFile(file) {
  const fd = new FormData(); fd.append('file', file);
  $('#bundleResult').innerHTML = '<div class="bundle-res"><div class="chip">Verifying...</div></div>';
  let r;
  try { r = await api('/api/evidence/verify', { method: 'POST', form: fd }); }
  catch (e) { r = { error: `Verification failed: ${e.message}` }; }
  $('#bundleResult').innerHTML = r.error ? `<div class="bundle-res"><div class="chip bad">${esc(r.error)}</div></div>` : `
    <div class="bundle-res"><div class="vc ${r.ok ? 'ok' : 'bad'}"><div class="k">${esc(file.name)}</div><div class="v"><svg><use href="#${r.ok ? 'i-check' : 'i-alert'}"/></svg>${r.ok ? 'Authentic' : 'NOT authentic'}</div>
    <div class="d">Signature ${r.signature_valid ? 'valid' : 'INVALID'} &middot; ${r.signed_by_this_installation ? 'signed by this installation' : 'UNKNOWN signing key'} &middot; alert #${esc(r.alert_id)} exported by ${esc(r.exported_by)}</div></div>
    ${r.files.map((f) => `<div class="row"><span class="mono">${esc(f.file)}</span><span style="color:${f.ok ? 'var(--s-good)' : 'var(--s-crit)'};font-weight:700">${esc(f.status)}</span></div>`).join('')}</div>`;
}

// ------------------------------------------------------------------ sources / replay
async function loadSamples() {
  const list = await api('/api/samples');
  $('#sampleList').innerHTML = list.length ? list.map((s) => `
    <div class="sample"><span class="mono small">${esc(s.name)}</span><button class="btn btn-accent btn-sm" data-sample="${esc(s.name)}" type="button"><svg><use href="#i-play"/></svg>Analyse</button>
    <span class="m">${s.width}x${s.height} &middot; ${s.fps} fps &middot; ${Math.round(s.frames / Math.max(1, s.fps))} s &middot; ${s.size_mb} MB</span></div>`).join('')
    : '<div class="empty">No sample videos found in samples/ or project_documents/.</div>';
}
function startReplay(streamId, title) {
  S.replayStream?.close();
  $('#replayTitle').textContent = title;
  $('#replayEmpty').style.display = ''; $('#replayEmpty').innerHTML = '<div class="spinner"></div><span>Loading detector and first frames</span>';
  $('#replayAlerts').innerHTML = ''; $('#replayProg').style.width = '0';
  S.replayStream = new StreamView(streamId, $('#replayImg'), {
    emptyEl: $('#replayEmpty'),
    onFrame: (m) => {
      if (m.type === 'done') { $('#replayStat').textContent = 'finished'; return; }
      if (m.type === 'error') { $('#replayStat').textContent = 'error'; toast('Replay error', m.message, 'critical'); return; }
      $('#replayStat').textContent = `P ${m.people_count} · V ${m.vehicle_count} · ${m.step_ms} ms/frame${m.night_mode ? ' · IR' : ''}`;
      if (m.progress?.total) $('#replayProg').style.width = `${(100 * m.progress.pos) / m.progress.total}%`;
      m.alerts.forEach((a) => $('#replayAlerts').insertAdjacentHTML('afterbegin',
        `<div class="ac ${a.severity}" data-id="${a.id}"><div class="bar"></div><div><div class="top">${sevBadge(a.severity)}<span class="muted small">t+${a.timestamp.toFixed(1)}s</span></div><div class="msg">${esc(a.message)}</div></div></div>`));
    },
  });
}

// ------------------------------------------------------------------ system + calibration
async function enterSystem() {
  const s = await api('/api/system/status');
  const row = (name, val, sub, good = true) => `<div class="sys"><b>${esc(name)}</b><span class="${good ? '' : 'err'}" style="color:${good ? 'var(--s-good)' : ''}">${esc(val)}</span><span class="s">${esc(sub)}</span></div>`;
  $('#sysComponents').innerHTML = [
    row('API server', `v${s.version}`, `${s.platform}, Python ${s.python}, up ${Math.round(s.uptime_s / 60)} min`),
    row('Real-footage detector', s.detector.real_footage_backend, s.detector.yolo_loaded ? 'YOLOv8n loaded, shared by all streams' : (s.detector.yolo_installed ? 'loads on first real video' : 'ultralytics not installed: offline floor')),
    row('ANPR engines', s.anpr.engines.join(' + ') || 'none', `${s.anpr.processed} OCR jobs, ${s.anpr.reads} reads, queue ${s.anpr.queue}`, s.anpr.engines.length > 0),
    row('Active streams', String(s.streams.filter((x) => x.running).length), s.streams.map((x) => `${x.camera_id} ${x.fps}fps`).join(', ') || 'none'),
    row('Event bus', `${s.event_bus.subscribers} dashboards`, `${s.event_bus.published} messages published`),
    row('Storage', `${(s.storage.db_bytes / 1e6).toFixed(1)} MB`, `${s.storage.counts.alerts} alerts, ${s.storage.counts.audit_log} chained records, ${s.storage.snapshots} evidence frames`),
    row('Signing key', 'Ed25519', `fingerprint ${s.signing_key.fingerprint}`),
  ].join('');
  loadCalib();
}
async function loadCalib() {
  const cam = $('#calCam').value || 'cam-01';
  S.calib.geom = await api(`/api/zones/${cam}`);
  S.calib.frameW = S.calib.geom.frame_w; S.calib.frameH = S.calib.geom.frame_h; S.calib.pts = [];
  const f = S.lastFrame[cam];
  if (f) $('#calImg').src = 'data:image/jpeg;base64,' + f.jpeg_b64;
  else {
    const sv = new StreamView(cam, $('#calImg'), { onFrame: (m) => { if (m.type === 'frame') { S.lastFrame[cam] = m; sv.close(); } } });
  }
  drawCalib(); updateCalHint();
}
function calibRect() {
  const c = $('#calCanvas'), r = c.getBoundingClientRect();
  const k = Math.min(r.width / S.calib.frameW, r.height / S.calib.frameH);
  const w = S.calib.frameW * k, h = S.calib.frameH * k;
  return { r, k, ox: (r.width - w) / 2, oy: (r.height - h) / 2 };
}
function drawCalib() {
  const c = $('#calCanvas'), { r, k, ox, oy } = calibRect();
  c.width = r.width * devicePixelRatio; c.height = r.height * devicePixelRatio;
  const ctx = c.getContext('2d'); ctx.scale(devicePixelRatio, devicePixelRatio); ctx.clearRect(0, 0, r.width, r.height);
  const P = ([x, y]) => [ox + x * k, oy + y * k];
  ctx.lineWidth = 2; ctx.font = '12px sans-serif';
  (S.calib.geom?.zones || []).forEach((z) => { ctx.strokeStyle = 'rgba(255,90,90,.5)'; ctx.setLineDash([6, 4]); ctx.beginPath(); z.polygon.forEach((p, i) => (i ? ctx.lineTo(...P(p)) : ctx.moveTo(...P(p)))); ctx.closePath(); ctx.stroke(); });
  (S.calib.geom?.lines || []).forEach((l) => { ctx.setLineDash([]); ctx.strokeStyle = 'rgba(255,60,60,.6)'; ctx.beginPath(); ctx.moveTo(...P(l.p1)); ctx.lineTo(...P(l.p2)); ctx.stroke(); });
  ctx.setLineDash([]); ctx.strokeStyle = '#19c3a6'; ctx.fillStyle = 'rgba(25,195,166,.18)'; ctx.lineWidth = 3;
  const pts = S.calib.pts.map(P);
  if (pts.length) {
    ctx.beginPath(); pts.forEach((p, i) => (i ? ctx.lineTo(...p) : ctx.moveTo(...p)));
    if (S.calib.mode === 'zone' && pts.length > 2) { ctx.closePath(); ctx.fill(); }
    ctx.stroke();
    pts.forEach((p) => { ctx.beginPath(); ctx.arc(p[0], p[1], 5, 0, 7); ctx.fillStyle = '#19c3a6'; ctx.fill(); });
  }
}
function updateCalHint() {
  const n = S.calib.pts.length;
  $('#calHint').textContent = S.calib.mode === 'line'
    ? (n < 2 ? `Click ${2 - n} more point(s) to draw the fence line.` : 'Line ready. Choose the alert direction and Save.')
    : (n < 3 ? `Click at least ${3 - n} more point(s) for the restricted zone.` : `${n} points. Keep clicking to refine, or Save.`);
  $('#calDir').style.display = S.calib.mode === 'line' ? '' : 'none';
}
async function saveCalib() {
  const cam = $('#calCam').value, g = S.calib.geom, name = $('#calName').value.trim() || (S.calib.mode === 'line' ? 'Fence Line' : 'Restricted Zone');
  const body = { replace: true, zones: g.zones.map(({ name: n, polygon, zone_type }) => ({ name: n, polygon, zone_type })), lines: g.lines.map(({ name: n, p1, p2, unauthorized_side }) => ({ name: n, p1, p2, unauthorized_side })) };
  if (S.calib.mode === 'line') {
    if (S.calib.pts.length !== 2) { toast('Draw the line first', 'Click two points on the frame'); return; }
    body.lines = [{ name, p1: S.calib.pts[0], p2: S.calib.pts[1], unauthorized_side: $('#calDir').value }];
  } else {
    if (S.calib.pts.length < 3) { toast('Draw the zone first', 'Click at least three points'); return; }
    body.zones = [{ name, polygon: S.calib.pts, zone_type: 'restricted' }];
  }
  await api(`/api/zones/${cam}`, { method: 'POST', body });
  toast('Calibration saved', `${camName(cam)}: analytics now use the new ${S.calib.mode}`, 'ok');
  loadCalib();
}

// ------------------------------------------------------------------ guided demo
const TOUR = [
  { view: 'command', title: 'One command center for every border camera', text: 'IBVAP turns the CCTV a post already has into an analytics network. Four site cameras are being analysed live; the site threat level in the top bar is computed from every open alert.' },
  { view: 'command', spot: '#mainFeed', title: 'Detect, track, understand', text: 'Each person and vehicle keeps a stable ID across frames, which is what lets IBVAP reason over time: loitering, fence crossings in the forbidden direction, groups and convoys, erratic running, night movement.', run: () => setMainCam('cam-01') },
  { view: 'command', spot: '#mainFeed', title: 'ANPR with an OCR-tolerant watchlist', text: 'At the check post every plate is read and matched against the watchlist. Misreads such as 8/B or 1/I still match. A hit raises a critical alert with the evidence frame attached.', run: () => setMainCam('cam-02') },
  { view: 'wall', spot: '#wall', title: 'All sectors at once', text: 'One pipeline per camera, shared by every viewer. The border of each tile follows that sector\'s live threat level.' },
  { view: 'incidents', spot: '#incTable', title: 'Every alert becomes an incident', text: 'Operators acknowledge, investigate, escalate or resolve. Each step is written into the hash chain with the operator\'s name, so the chain of custody cannot be quietly edited.', run: async () => { await loadIncidents(); const r = $('#incTable tbody tr[data-id]'); if (r) openIncident(r.dataset.id); } },
  { view: 'intel', spot: '.traj-panel', title: 'Follow a vehicle across posts', text: 'Sightings from every camera are joined by plate, so a wanted vehicle\'s route across the site is reconstructed automatically.', run: async () => { closeDrawer(); await loadIntelLists(); const w = $('.pl .plate.watch')?.closest('.pl') || $('.pl'); if (w) showTrajectory(w.dataset.plate); } },
  { view: 'analytics', title: 'The operational picture', text: 'Alerts over time by severity, by type and by sector, and live occupancy. Click any bar to jump to the matching incidents.' },
  { view: 'audit', spot: '.attack-steps', title: 'Evidence that holds up', text: 'Three attacks, three detections. The third one rewrites the whole hash chain, which fools a plain chain. The Ed25519-signed checkpoint still catches it, because the key is not in the database.', run: async () => { await runAttack('seed'); await runAttack('attack3'); } },
  { view: 'sources', title: 'Real footage, same pipeline', text: 'Analyse recorded clips or connect an RTSP camera. YOLOv8 detection, tracking, ANPR and every behaviour rule run exactly as in the live demo.' },
  { view: 'command', title: 'Back to a clean, signed chain', text: 'The tamper demo is cleared and a fresh signed chain has started. The watchlist is kept. IBVAP keeps watching every sector.',
    run: async () => { await api('/api/data/reset', { method: 'POST' }); S.streamAlerts = []; renderStream(); S.verify = null; await refreshVerify(); loadKpis(); } },
];
let tourIdx = -1;
async function tourGo(i) {
  $$('.spot').forEach((e) => e.classList.remove('spot'));
  if (i < 0 || i >= TOUR.length) { $('#coach').hidden = true; tourIdx = -1; return; }
  tourIdx = i; const st = TOUR[i];
  if (location.hash.slice(1) !== st.view) location.hash = st.view; else showView(st.view);
  $('#coach').hidden = false;
  $('#coachStep').textContent = `${i + 1} / ${TOUR.length}`;
  $('#coachTitle').textContent = st.title; $('#coachText').textContent = st.text;
  $('#coachPrev').disabled = i === 0; $('#coachNext').textContent = i === TOUR.length - 1 ? 'Finish' : 'Next';
  try { await st.run?.(); } catch (e) { console.warn(e); }
  if (st.spot) setTimeout(() => $(st.spot)?.classList.add('spot'), 250);
}

// ------------------------------------------------------------------ wiring
function wire() {
  $('#btnMenu').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#camTabs').addEventListener('click', (e) => { const b = e.target.closest('[data-cam]'); if (b) setMainCam(b.dataset.cam); });
  $('#sectorList').addEventListener('click', (e) => { const b = e.target.closest('[data-cam]'); if (b) setMainCam(b.dataset.cam); });
  $('#tglHeat').addEventListener('change', (e) => { $('#mainFeed').classList.toggle('show-heat', e.target.checked); refreshHeat(); });
  $('#btnSnapshot').addEventListener('click', () => {
    const a = Object.assign(document.createElement('a'), { href: $('#feedImg').src, download: `${S.mainCam}_${Date.now()}.jpg` });
    a.click();
  });
  $('#sevFilter').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; S.sevFilter = b.dataset.sev; $$('#sevFilter button').forEach((x) => x.classList.toggle('on', x === b)); renderStream(); });
  $('#alertStream').addEventListener('click', (e) => { const c = e.target.closest('[data-id]'); if (c && c.dataset.id !== 'null') openIncident(c.dataset.id); });
  $('#replayAlerts').addEventListener('click', (e) => { const c = e.target.closest('[data-id]'); if (c && c.dataset.id !== 'null') openIncident(c.dataset.id); });

  ['#fSev', '#fStatus', '#fCam', '#fType'].forEach((id) => $(id).addEventListener('change', loadIncidents));
  $('#fQ').addEventListener('input', () => debounce('q', loadIncidents, 300));
  $('#incTable tbody').addEventListener('click', (e) => { if (e.target.matches('input')) return; const tr = e.target.closest('tr[data-id]'); if (tr) openIncident(tr.dataset.id); });
  $('#incAll').addEventListener('change', (e) => $$('#incTable tbody input').forEach((c) => { c.checked = e.target.checked; }));
  $('#btnBulkAck').addEventListener('click', async () => {
    const ids = $$('#incTable tbody input:checked').map((c) => +c.value);
    if (!ids.length) { toast('Select incidents first', 'Use the checkboxes on the left'); return; }
    const r = await api('/api/alerts/bulk', { method: 'POST', body: { ids, action: 'acknowledged' } });
    toast(`${r.updated} incidents acknowledged`, `by ${session.operator}`, 'ok'); loadIncidents(); loadKpis();
  });
  $('#btnShift').href = link('/api/reports/shift');
  $('#btnIntegrityReport').href = link('/api/audit/report');
  $('#dwClose').addEventListener('click', closeDrawer); $('#scrim').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

  $('#plateQ').addEventListener('input', () => debounce('pq', loadIntelLists, 250));
  $('#plateList').addEventListener('click', (e) => { const p = e.target.closest('[data-plate]'); if (p) showTrajectory(p.dataset.plate); });
  $('#wlForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const r = await api('/api/intel/watchlist', { method: 'POST', body: { plate: $('#wlPlate').value, reason: $('#wlReason').value, priority: $('#wlPrio').value } });
      toast('Added to watchlist', `${r.plate}${r.format_valid ? '' : ' (not a standard Indian format)'}`, 'ok');
      $('#wlPlate').value = ''; $('#wlReason').value = ''; loadIntelLists();
    } catch (err) { toast('Could not add', err.message, 'critical'); }
  });
  $('#wlList').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-del]'); if (!b) return;
    await api(`/api/intel/watchlist/${encodeURIComponent(b.dataset.del)}`, { method: 'DELETE' });
    toast('Removed from watchlist', b.dataset.del, 'ok'); loadIntelLists();
  });
  const testMatch = async () => {
    const v = $('#mtInput').value.trim(); if (!v) return;
    const r = await api('/api/intel/match?plate=' + encodeURIComponent(v));
    $('#mtOut').innerHTML = r.match
      ? `Read <span class="plate">${esc(r.read)}</span> matches <span class="plate watch">${esc(r.match.plate)}</span> (${esc(r.match.type.replace('_', '-'))} match)`
      : `Read <span class="plate">${esc(r.read)}</span>, repaired to <span class="plate">${esc(r.repaired)}</span>: no watchlist match${r.format_valid ? '' : ', format unverified'}`;
  };
  $('#mtBtn').addEventListener('click', testMatch); $('#mtInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') testMatch(); });

  $('#rangeSeg').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; S.rangeMin = +b.dataset.min; $$('#rangeSeg button').forEach((x) => x.classList.toggle('on', x === b)); loadAnalytics(); });
  $('#occCam').addEventListener('change', loadOccupancy);

  $('#btnVerify').addEventListener('click', async () => { const v = await api('/api/audit/verify'); S.verify = v; setChainChip(v); renderVerify(v, true); loadChain(); });
  $$('[data-attack]').forEach((b) => b.addEventListener('click', () => runAttack(b.dataset.attack)));
  const dz = $('#dropzone');
  $('#bundleFile').addEventListener('change', (e) => e.target.files[0] && verifyBundleFile(e.target.files[0]));
  ['dragover', 'dragenter'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, () => dz.classList.remove('drag')));
  dz.addEventListener('drop', (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) verifyBundleFile(f); });

  $('#sampleList').addEventListener('click', async (e) => {
    const b = e.target.closest('[data-sample]'); if (!b) return;
    b.disabled = true;
    try { const r = await api(`/api/replay/sample?name=${encodeURIComponent(b.dataset.sample)}`, { method: 'POST' }); startReplay(r.stream_id, `Replay: ${b.dataset.sample}`); }
    catch (err) { toast('Could not start replay', err.message, 'critical'); }
    b.disabled = false;
  });
  $('#uploadFile').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    const fd = new FormData(); fd.append('file', f);
    toast('Uploading', f.name);
    try { const r = await api('/api/replay/start?camera_id=cam-upload', { method: 'POST', form: fd }); startReplay(r.stream_id, `Replay: ${f.name}`); }
    catch (err) { toast('Upload failed', err.message, 'critical'); }
    e.target.value = '';
  });
  $('#rtspForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = $('#rtspUrl').value.trim(); if (!url) return;
    toast('Connecting to camera', url.replace(/\/\/[^@]*@/, '//***@'));
    try { const r = await api(`/api/live/rtsp/connect?camera_id=cam-rtsp&rtsp_url=${encodeURIComponent(url)}`, { method: 'POST' }); startReplay(r.stream_id, 'Live RTSP camera'); }
    catch (err) { toast('RTSP connection failed', err.message, 'critical'); }
  });
  $('#btnStopReplay').addEventListener('click', () => { S.replayStream?.close(); S.replayStream = null; $('#replayStat').textContent = 'stopped'; });

  $('#calCam').addEventListener('change', loadCalib);
  $('#calMode').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; S.calib.mode = b.dataset.mode; S.calib.pts = []; $$('#calMode button').forEach((x) => x.classList.toggle('on', x === b)); $('#calName').value = b.dataset.mode === 'line' ? 'Fence Line' : 'Restricted Zone'; drawCalib(); updateCalHint(); });
  $('#calCanvas').addEventListener('click', (e) => {
    const { r, k, ox, oy } = calibRect();
    const x = (e.clientX - r.left - ox) / k, y = (e.clientY - r.top - oy) / k;
    if (x < 0 || y < 0 || x > S.calib.frameW || y > S.calib.frameH) return;
    if (S.calib.mode === 'line' && S.calib.pts.length >= 2) S.calib.pts = [];
    S.calib.pts.push([Math.round(x), Math.round(y)]); drawCalib(); updateCalHint();
  });
  $('#calClear').addEventListener('click', () => { S.calib.pts = []; drawCalib(); updateCalHint(); });
  $('#calSave').addEventListener('click', saveCalib);
  $('#calDefault').addEventListener('click', async () => { await api(`/api/zones/${$('#calCam').value}`, { method: 'DELETE' }); toast('Default geometry restored', camName($('#calCam').value), 'ok'); loadCalib(); });
  window.addEventListener('resize', () => debounce('rs', () => { if (S.view === 'system') drawCalib(); if (S.view === 'analytics') loadAnalytics(); }, 200));
  $('#btnReset').addEventListener('click', async () => {
    if (!confirm('Clear all alerts, events, sightings and the audit chain? The watchlist is kept. This cannot be undone.')) return;
    await api('/api/data/reset', { method: 'POST' }); S.streamAlerts = []; renderStream(); S.verify = null; loadKpis(); toast('Tracking data cleared', 'A fresh signed chain has started', 'ok');
  });

  $('#btnTheme').addEventListener('click', () => {
    const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = t; try { localStorage.setItem('ibvap.theme', t); } catch { /* ignore */ }
    if (S.view === 'analytics') loadAnalytics();
  });
  $('#btnSound').addEventListener('click', () => { S.sound = !S.sound; $('#btnSound').classList.toggle('on', S.sound); if (S.sound) beep(660, 0.08); });
  $('#operatorChip').addEventListener('click', () => {
    const n = prompt('Operator name for the chain of custody', session.operator);
    if (n && n.trim()) { session.setOperator(n.trim().slice(0, 40)); renderOperator(); }
  });
  $('#btnTour').addEventListener('click', () => tourGo(0));
  $('#coachNext').addEventListener('click', () => tourGo(tourIdx + 1));
  $('#coachPrev').addEventListener('click', () => tourGo(tourIdx - 1));
  $('#coachClose').addEventListener('click', () => tourGo(-1));
}
function renderOperator() {
  $('#opName').textContent = session.operator;
  $('#opAvatar').textContent = session.operator.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase();
}

async function boot() {
  try { const t = localStorage.getItem('ibvap.theme'); if (t) document.documentElement.dataset.theme = t; } catch { /* ignore */ }
  setInterval(() => { $('#clock').textContent = new Date().toLocaleTimeString([], { hour12: false }); }, 1000);
  wire(); renderOperator();
  if (!(await authenticate())) {
    $('#gate').hidden = false;
    $('#gateForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (await tryKey($('#gateKey').value.trim())) { $('#gate').hidden = true; start(); }
      else $('#gateErr').textContent = 'That key was rejected.';
    });
    return;
  }
  start();
}
async function start() {
  await loadCameras();
  renderCamTabs(); renderSectors();
  try { onThreat(await api('/api/analytics/threat')); } catch { /* bus will update */ }
  try { S.streamAlerts = (await api('/api/alerts?limit=30')).map((a) => a); renderStream(); } catch { /* empty */ }
  try { S.watchPlates = new Set((await api('/api/intel/watchlist')).map((w) => w.plate)); } catch { /* empty */ }
  connectBus();
  showView(location.hash.slice(1) || 'command');
  setInterval(() => { if (S.view === 'command') { loadKpis(); refreshHeat(); } }, 5000);
  setInterval(refreshVerify, 15000);
}
boot();
