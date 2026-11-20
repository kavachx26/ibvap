// API client: auth, operator identity, REST + WebSocket helpers.
const DEFAULT_KEY = 'ibvap-demo-key-2026-CHANGE-ME';
const ORIGIN = location.protocol.startsWith('http') ? location.origin : 'http://localhost:8000';

function load(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } }
function save(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } }

export const session = {
  key: load('ibvap.key', DEFAULT_KEY),
  operator: load('ibvap.operator', 'Duty Officer'),
  setKey(k) { this.key = k; save('ibvap.key', k); },
  setOperator(n) { this.operator = n; save('ibvap.operator', n); },
};

export class ApiError extends Error {
  constructor(status, detail) { super(detail || `HTTP ${status}`); this.status = status; }
}

export async function api(path, { method = 'GET', body, form, raw } = {}) {
  const headers = { 'X-API-Key': session.key, 'X-Operator': session.operator };
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(ORIGIN + path, { method, headers, body: payload });
  if (!res.ok) {
    let detail = '';
    try { detail = (await res.json()).detail; } catch { /* not json */ }
    throw new ApiError(res.status, typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  if (raw) return res;
  const ct = res.headers.get('content-type') || '';
  return ct.includes('json') ? res.json() : res.text();
}

export function wsUrl(path) {
  const u = new URL(ORIGIN + path);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.searchParams.set('api_key', session.key);
  return u.toString();
}

export function link(path) {
  const u = new URL(ORIGIN + path);
  u.searchParams.set('api_key', session.key);
  return u.toString();
}

export async function authenticate() {
  for (const k of [session.key, DEFAULT_KEY]) {
    try {
      const r = await fetch(ORIGIN + '/api/analytics/threat', { headers: { 'X-API-Key': k } });
      if (r.ok) { session.setKey(k); return true; }
    } catch { return false; }
  }
  return false;
}

export async function tryKey(k) {
  const r = await fetch(ORIGIN + '/api/analytics/threat', { headers: { 'X-API-Key': k } });
  if (r.ok) session.setKey(k);
  return r.ok;
}

/** A WebSocket that reconnects with backoff until closed on purpose. */
export class LiveSocket {
  constructor(path, onMessage, onState = () => {}) {
    this.path = path; this.onMessage = onMessage; this.onState = onState;
    this.closed = false; this.retry = 0; this.open();
  }
  open() {
    if (this.closed) return;
    const ws = new WebSocket(wsUrl(this.path));
    this.ws = ws;
    ws.onopen = () => { this.retry = 0; this.onState('open'); };
    ws.onmessage = (e) => { try { this.onMessage(JSON.parse(e.data)); } catch (err) { console.error(err); } };
    ws.onclose = (e) => {
      this.onState('closed', e.code);
      if (this.closed || e.code === 4401) return;
      const delay = Math.min(8000, 500 * 2 ** this.retry++);
      this.timer = setTimeout(() => this.open(), delay);
    };
    ws.onerror = () => ws.close();
  }
  close() { this.closed = true; clearTimeout(this.timer); try { this.ws?.close(); } catch { /* ignore */ } }
}
