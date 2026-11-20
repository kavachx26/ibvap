// Small dependency-free SVG charts (offline-safe). Thin marks, rounded
// data-ends on the baseline, a 2px surface gap between stacked segments,
// recessive grid, and a hover tooltip on every mark.
const NS = 'http://www.w3.org/2000/svg';
let tipEl;

function tip() {
  if (!tipEl) { tipEl = document.createElement('div'); tipEl.className = 'tip'; document.body.appendChild(tipEl); }
  return tipEl;
}
export function showTip(e, html) {
  const t = tip(); t.innerHTML = html; t.style.display = 'block';
  const x = Math.min(window.innerWidth - t.offsetWidth - 12, e.clientX + 14);
  const y = Math.min(window.innerHeight - t.offsetHeight - 12, e.clientY + 14);
  t.style.left = x + 'px'; t.style.top = y + 'px';
}
export function hideTip() { if (tipEl) tipEl.style.display = 'none'; }

function el(tag, attrs = {}, parent) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return v;
}

/** Path for a bar whose top corners are rounded (r) and bottom is square. */
function topRounded(x, y, w, h, r) {
  r = Math.min(r, w / 2, h);
  if (h <= 0) return '';
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

/** Stacked columns. buckets: [{t, a, b...}], keys: [{key, label, color}] */
export function stackedColumns(host, buckets, keys, { fmtX = (t) => t, height = 230 } = {}) {
  host.innerHTML = '';
  const W = Math.max(320, host.clientWidth || 600), H = height;
  const m = { l: 34, r: 8, t: 10, b: 24 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const totals = buckets.map((b) => keys.reduce((s, k) => s + (b[k.key] || 0), 0));
  const max = niceMax(Math.max(1, ...totals));
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' }, host);
  const g = el('g', { class: 'grid' }, svg);
  for (let i = 0; i <= 4; i++) {
    const y = m.t + ih - (ih * i) / 4;
    el('line', { x1: m.l, x2: W - m.r, y1: y, y2: y }, g);
    const tx = el('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end' }, svg);
    tx.textContent = Math.round((max * i) / 4);
  }
  const n = buckets.length, slot = iw / Math.max(1, n), bw = Math.max(2, Math.min(28, slot * 0.68));
  const labelEvery = Math.ceil(n / 8);
  buckets.forEach((b, i) => {
    const x = m.l + i * slot + (slot - bw) / 2;
    let y = m.t + ih;
    const segs = keys.filter((k) => b[k.key] > 0);
    segs.forEach((k, j) => {
      const h = (b[k.key] / max) * ih;
      const gap = j > 0 ? 2 : 0;
      const top = j === segs.length - 1;
      const yy = y - h;
      if (top) el('path', { d: topRounded(x, yy, bw, Math.max(0, h - gap), 4), fill: k.color }, svg);
      else el('rect', { x, y: yy, width: bw, height: Math.max(0, h - gap), fill: k.color }, svg);
      y = yy;
    });
    if (i % labelEvery === 0) {
      const tx = el('text', { x: m.l + i * slot + slot / 2, y: H - 6, 'text-anchor': 'middle' }, svg);
      tx.textContent = fmtX(b.t);
    }
    const hit = el('rect', { class: 'hit', x: m.l + i * slot, y: m.t, width: slot, height: ih }, svg);
    hit.addEventListener('mousemove', (e) => showTip(e, `<b>${esc(fmtX(b.t))}</b>` + keys.map((k) =>
      `<div class="r"><span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${k.color};margin-right:5px"></i>${k.label}</span><span>${b[k.key] || 0}</span></div>`).join('')
      + `<div class="r"><span>Total</span><span>${totals[i]}</span></div>`));
    hit.addEventListener('mouseleave', hideTip);
  });
  if (!totals.some(Boolean)) {
    const tx = el('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle' }, svg);
    tx.textContent = 'No alerts in this window';
  }
}

/** Horizontal bars, single hue, value labels at the bar end. items: [{label, value, title?}] */
export function hBars(host, items, { color = 'var(--seq-5)', onClick } = {}) {
  host.innerHTML = '';
  if (!items.length) { host.innerHTML = '<div class="empty">No data yet</div>'; return; }
  const W = Math.max(300, host.clientWidth || 480);
  const row = 30, m = { l: 150, r: 44, t: 4 };
  const H = m.t + items.length * row + 4;
  const max = Math.max(1, ...items.map((d) => d.value));
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' }, host);
  const iw = W - m.l - m.r;
  items.forEach((d, i) => {
    const y = m.t + i * row;
    const lb = el('text', { class: 'lbl', x: m.l - 10, y: y + row / 2 + 4, 'text-anchor': 'end' }, svg);
    lb.textContent = d.label.length > 22 ? d.label.slice(0, 21) + '…' : d.label;
    const w = Math.max(d.value ? 3 : 0, (d.value / max) * iw);
    const bh = 14, by = y + (row - bh) / 2;
    if (w > 0) {
      const r = Math.min(4, w / 2);
      el('path', { d: `M${m.l},${by}H${m.l + w - r}Q${m.l + w},${by} ${m.l + w},${by + r}V${by + bh - r}Q${m.l + w},${by + bh} ${m.l + w - r},${by + bh}H${m.l}Z`, fill: d.color || color }, svg);
    }
    const v = el('text', { class: 'val', x: m.l + w + 6, y: y + row / 2 + 4 }, svg);
    v.textContent = d.value;
    const hit = el('rect', { class: 'hit', x: 0, y, width: W, height: row }, svg);
    hit.addEventListener('mousemove', (e) => showTip(e, `<b>${esc(d.title || d.label)}</b><div class="r"><span>Count</span><span>${d.value}</span></div>`));
    hit.addEventListener('mouseleave', hideTip);
    if (onClick) hit.addEventListener('click', () => onClick(d));
  });
}

/** Line chart with crosshair tooltip. series: [{name, color, points:[{x,y}]}] (one y-axis) */
export function lineChart(host, series, { fmtX = (x) => x, height = 220 } = {}) {
  host.innerHTML = '';
  const pts = series.flatMap((s) => s.points);
  if (!pts.length) { host.innerHTML = '<div class="empty">No samples yet. Open this camera\'s stream.</div>'; return; }
  const W = Math.max(320, host.clientWidth || 600), H = height;
  const m = { l: 30, r: 10, t: 10, b: 24 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const x0 = Math.min(...pts.map((p) => p.x)), x1 = Math.max(...pts.map((p) => p.x));
  const max = niceMax(Math.max(1, ...pts.map((p) => p.y)));
  const sx = (x) => m.l + ((x - x0) / Math.max(1e-9, x1 - x0)) * iw;
  const sy = (y) => m.t + ih - (y / max) * ih;
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img' }, host);
  const g = el('g', { class: 'grid' }, svg);
  for (let i = 0; i <= 4; i++) {
    const y = m.t + ih - (ih * i) / 4;
    el('line', { x1: m.l, x2: W - m.r, y1: y, y2: y }, g);
    const tx = el('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end' }, svg);
    tx.textContent = Math.round((max * i) / 4);
  }
  for (let i = 0; i <= 4; i++) {
    const xv = x0 + ((x1 - x0) * i) / 4;
    const tx = el('text', { x: sx(xv), y: H - 6, 'text-anchor': 'middle' }, svg);
    tx.textContent = fmtX(xv);
  }
  series.forEach((s) => {
    if (!s.points.length) return;
    el('path', { d: s.points.map((p, i) => `${i ? 'L' : 'M'}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(''),
      fill: 'none', stroke: s.color, 'stroke-width': 2, 'stroke-linejoin': 'round' }, svg);
    const last = s.points[s.points.length - 1];
    const lab = el('text', { x: Math.min(W - m.r - 4, sx(last.x)), y: sy(last.y) - 8, 'text-anchor': 'end', class: 'lbl' }, svg);
    lab.textContent = s.name;
  });
  const cross = el('line', { y1: m.t, y2: m.t + ih, stroke: 'var(--line-2)', 'stroke-width': 1, visibility: 'hidden' }, svg);
  const hit = el('rect', { class: 'hit', x: m.l, y: m.t, width: iw, height: ih }, svg);
  hit.addEventListener('mousemove', (e) => {
    const r = svg.getBoundingClientRect();
    const xv = x0 + ((e.clientX - r.left) * (W / r.width) - m.l) / iw * (x1 - x0);
    cross.setAttribute('x1', sx(xv)); cross.setAttribute('x2', sx(xv)); cross.setAttribute('visibility', 'visible');
    const rows = series.map((s) => {
      const p = s.points.reduce((a, b) => (Math.abs(b.x - xv) < Math.abs(a.x - xv) ? b : a), s.points[0]);
      return `<div class="r"><span><i style="display:inline-block;width:8px;height:2px;background:${s.color};margin-right:5px;vertical-align:3px"></i>${s.name}</span><span>${p ? p.y : '-'}</span></div>`;
    }).join('');
    showTip(e, `<b>${esc(fmtX(xv))}</b>${rows}`);
  });
  hit.addEventListener('mouseleave', () => { hideTip(); cross.setAttribute('visibility', 'hidden'); });
}

/** Paints a normalised heat grid onto a canvas with a one-hue ramp. */
export function paintHeat(canvas, grid, w, h) {
  const ctx = canvas.getContext('2d');
  canvas.width = w; canvas.height = h;
  const img = ctx.createImageData(w, h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const v = Math.min(1, Math.sqrt(grid[y][x] || 0));
    const i = (y * w + x) * 4;
    // dark blue -> cyan -> near white
    img.data[i] = Math.round(30 + 200 * v * v);
    img.data[i + 1] = Math.round(80 + 170 * v);
    img.data[i + 2] = Math.round(160 + 95 * v);
    img.data[i + 3] = Math.round(v > 0.02 ? 70 + 185 * v : 0);
  }
  ctx.putImageData(img, 0, 0);
  canvas.style.imageRendering = 'auto';
}
