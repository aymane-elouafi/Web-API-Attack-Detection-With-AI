'use strict';
/* Aegis console: vanilla JS, no dependencies. All text from traffic goes through textContent (h()), never innerHTML. */
const $ = id => document.getElementById(id);
const h = (tag, attrs, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else if (v === true) e.setAttribute(k, '');
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
};
const svg = (tag, attrs) => { const e = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };
const pct = x => (x * 100).toFixed(1) + '%';
const ago = ts => { const s = Math.max(0, Date.now() / 1000 - ts); return s < 90 ? Math.round(s) + 's ago' : s < 5400 ? Math.round(s / 60) + 'm ago' : s < 129600 ? Math.round(s / 3600) + 'h ago' : Math.round(s / 86400) + 'd ago'; };
const clock = ts => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let toastTimer;
const toast = msg => { const t = $('toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 3200); };

async function api(path, opts = {}) {
  let r;
  try { r = await fetch('/api' + path, { method: opts.method || (opts.body ? 'POST' : 'GET'), headers: { 'content-type': 'application/json' }, body: opts.body ? JSON.stringify(opts.body) : undefined }); }
  catch (e) { setGateway(false, true); throw e; }          // the console server itself did not answer
  if (r.status === 401) { showLogin(); throw new Error('login required'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.detail || data.error || r.statusText); e.status = r.status; if (r.status === 502) setGateway(false); throw e; }
  return data;
}
const gw = (p, o) => api('/gw' + p, o);
const act = async (fn, ok) => { try { const r = await fn(); if (ok) toast(ok); return r; } catch (e) { toast(e.message); throw e; } };

function ask(title, body, okLabel = 'Confirm') {
  $('dlgTitle').textContent = title; $('dlgBody').replaceChildren(...[].concat(body)); $('dlgOk').textContent = okLabel;
  const d = $('dlg'); d.showModal();
  return new Promise(res => d.addEventListener('close', () => res(d.returnValue === 'ok'), { once: true }));
}

/* ---- shared widgets ------------------------------------------------------------------------------ */
const riskClass = (risk, thr) => risk >= thr ? 'bad' : risk >= 0.3 ? 'warn' : '';
const riskChip = (risk, thr) => h('span', { class: 'chip ' + riskClass(risk, thr) }, risk.toFixed(2));
const actionChip = a => h('span', { class: 'chip ' + (a === 'blocked' ? 'bad' : a === 'would_block' ? 'warn' : '') }, a === 'would_block' ? 'would block' : a);
const bar = (v, cls = '') => h('div', { class: 'bar ' + cls }, h('i', { style: `width:${Math.min(100, v * 100)}%` }));
const empty = t => h('div', { class: 'empty' }, t);
const press = (el, fn) => { el.tabIndex = 0; el.addEventListener('keydown', ev => { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target === el) { ev.preventDefault(); fn(); } }); return el; };
const table = (cols, rows, onclick, none = 'Nothing here yet') => h('div', { class: 'wrap' }, h('table', {}, h('thead', {}, h('tr', {}, cols.map(c => h('th', {}, c)))),
  h('tbody', {}, rows.length ? rows.map(r => { const tr = h('tr', { class: onclick ? 'click' : '', onclick: onclick && (() => onclick(r)) }, r.cells.map(c => h('td', {}, c))); return onclick ? press(tr, () => onclick(r)) : tr; }) : h('tr', {}, h('td', { colspan: cols.length }, empty(none))))));
function highlight(text, terms) {
  const t = [...new Set(terms.map(x => x.trim()).filter(x => x.length >= 2))].sort((a, b) => b.length - a.length);
  if (!t.length || !text) return [text || ''];
  const re = new RegExp(t.map(x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'gi');
  const out = []; let last = 0, m;
  while ((m = re.exec(text))) { if (m.index > last) out.push(text.slice(last, m.index)); out.push(h('mark', {}, m[0])); last = m.index + m[0].length; if (!m[0]) re.lastIndex++; }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
function timeline(points) {
  const W = 800, H = 170, pad = 4, n = Math.max(points.length, 1), bw = W / n, max = Math.max(1, ...points.map(p => p.requests));
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Requests per minute' });
  points.forEach((p, i) => {
    const hh = (p.requests / max) * (H - pad), fh = (p.flagged / max) * (H - pad), x = i * bw + 1;
    const r1 = svg('rect', { x, y: H - hh, width: Math.max(1, bw - 2), height: hh, rx: 2, fill: 'var(--fill)' });
    const r2 = svg('rect', { x, y: H - fh, width: Math.max(1, bw - 2), height: fh, rx: 2, fill: 'var(--bad)' });
    for (const r of [r1, r2]) r.append(svg('title', {})); r1.firstChild.textContent = `${clock(p.t)}: ${p.requests} requests, ${p.flagged} flagged`;
    s.append(r1, r2);
  });
  return h('div', { class: 'timeline' }, s, h('div', { class: 'legend' }, h('span', {}, h('b', { style: 'background:var(--fill);border:1px solid var(--line)' }), 'Requests / min'), h('span', {}, h('b', { style: 'background:var(--bad)' }), 'Flagged')));
}

/* ---- drawer ------------------------------------------------------------------------------------- */
let drawerOpen = false, drawerFrom = null;
function openDrawer(title, body) {
  $('drawerTitle').textContent = title; $('drawerBody').replaceChildren(body);
  if (!drawerOpen) drawerFrom = document.activeElement;
  $('drawer').inert = false; $('drawer').classList.add('open'); $('drawer').setAttribute('aria-hidden', 'false'); $('drawerScrim').hidden = false; drawerOpen = true;
  $('drawerClose').focus();
}
function closeDrawer() {
  const was = drawerOpen;
  $('drawer').classList.remove('open'); $('drawer').setAttribute('aria-hidden', 'true'); $('drawer').inert = true; $('drawerScrim').hidden = true; drawerOpen = false;
  if (was && drawerFrom && document.contains(drawerFrom)) drawerFrom.focus();
  drawerFrom = null;
}
addEventListener('focusin', e => { if (drawerOpen && !$('dlg').open && !$('drawer').contains(e.target)) $('drawerClose').focus(); });
$('drawerClose').onclick = $('drawerScrim').onclick = closeDrawer;
addEventListener('keydown', e => { if (e.key === 'Escape' && drawerOpen) closeDrawer(); });

async function openEvent(id, onChange) {
  const x = await act(() => api('/explain/' + id)), ev = x.event, thr = x.threshold, flagged = ev.action !== 'allowed';
  const terms = x.terms.filter(t => t.source === 'rules' || t.text.length >= 3).map(t => t.text).filter(Boolean);
  const detectors = Object.entries(ev.detectors).filter(([k]) => !['deny_list', 'rate_limit'].includes(k));
  const fb = h('span', { class: 'muted' }, ev.feedback ? `You marked this ${ev.feedback.verdict}.` : '');
  const exemptForm = h('div', { class: 'stack', hidden: true });
  const top = detectors.sort((a, b) => b[1] - a[1])[0];
  const body = h('div', { class: 'stack' },
    h('div', {}, h('div', { class: 'row' }, actionChip(ev.action), h('span', { class: 'muted' }, `${clock(ev.ts)} · ${ev.client_ip} · status ${ev.upstream_status} · ${ev.latency_ms.toFixed(1)} ms in engine`)),
      h('div', { class: 'meter ' + (ev.risk >= thr ? 'flag' : '') }, h('i', { style: `width:${ev.risk * 100}%` }), h('u', { style: `left:${thr * 100}%`, title: 'threshold' })),
      h('div', { class: 'row muted' }, h('span', {}, `Risk ${ev.risk.toFixed(2)}`), h('span', { class: 'grow' }), h('span', {}, `Threshold ${thr}`))),
    h('div', {}, h('h3', {}, 'Why'), h('div', { class: 'stack', style: 'margin-top:8px' }, detectors.length ? detectors.map(([k, v]) => h('div', {}, h('div', { class: 'row' }, h('b', {}, k), h('span', { class: 'grow' }), h('span', { class: 'mono' }, v.toFixed(2))), bar(v, v >= .5 ? 'bad' : ''))) : h('span', { class: 'muted' }, 'No detector fired.')),
      h('p', { class: 'muted' }, 'Each detector gives a strength between 0 and 1. They are combined as 1 − ∏(1 − strength), so one confident detector is enough and several doubtful ones add up.')),
    x.terms.length ? h('div', {}, h('h3', {}, 'Evidence'), h('div', { style: 'margin-top:8px' }, x.terms.map(t => h('span', { class: 'chip' }, t.source === 'rules' ? `${t.rule} · ${t.name}` : `ML n-gram “${t.text}” +${t.weight}`)))) : null,
    x.exempt.length ? h('div', { class: 'chip good' }, 'An exemption silenced: ' + x.exempt.map(r => r.detector).join(', ')) : null,
    h('div', {}, h('h3', {}, 'Request'), h('pre', { class: 'req', style: 'margin-top:8px' }, highlight(`${ev.method} ${ev.path}${ev.query ? '?' + ev.query : ''}`, terms), x.decoded.query ? ['\n\ndecoded: ', highlight(x.decoded.query, terms)] : '', x.decoded.body ? ['\n\nbody: ', highlight(x.decoded.body, terms)] : '', '\n\nuser-agent: ', highlight(ev.user_agent, terms))),
    ev.detectors.behavior != null || ev.reasons.some(r => r.detector === 'behavior') ? behaviorBox(ev) : null,
    schemaBox(ev),
    h('div', { class: 'stack' }, h('h3', {}, 'Decide'), h('div', { class: 'row' },
      h('button', { class: 'btn primary', onclick: async () => { await act(() => api('/gw/feedback', { body: { event_id: id, verdict: 'benign' } }), 'Marked benign. See the Learning Inbox.'); fb.textContent = 'You marked this benign.'; onChange && onChange(); } }, 'Not an attack'),
      h('button', { class: 'btn', onclick: async () => { await act(() => api('/gw/feedback', { body: { event_id: id, verdict: 'attack' } }), 'Marked as a real attack'); fb.textContent = 'You marked this attack.'; onChange && onChange(); } }, 'Real attack'),
      h('button', { class: 'btn', onclick: () => { exemptForm.hidden = !exemptForm.hidden; } }, 'Exempt…'),
      h('button', { class: 'btn danger', onclick: async () => { if (await ask('Ban ' + ev.client_ip + '?', 'Every request from this address will get 403 until you remove it under Policies.', 'Ban')) { await act(() => gw('/lists', { body: { ip: ev.client_ip, kind: 'deny', note: 'banned from event ' + id } }), 'Banned ' + ev.client_ip); onChange && onChange(); } } }, 'Ban IP')),
      fb, exemptForm));
  exemptFormFill(exemptForm, ev, top ? top[0] : 'rules');
  openDrawer(`${ev.method} ${ev.path}`, body);
}
function behaviorBox(ev) {
  const r = ev.reasons.find(r => r.detector === 'behavior'); if (!r || typeof r.detail !== 'object') return null;
  return h('div', {}, h('h3', {}, 'Client behavior (last 60 s)'), h('div', { class: 'row', style: 'margin-top:8px' }, Object.entries(r.detail).map(([k, v]) => h('span', { class: 'chip' }, `${k.replace(/_/g, ' ')}: ${v}`))));
}
function schemaBox(ev) {
  const r = ev.reasons.find(r => r.detector === 'schema'); if (!r) return null;
  return h('div', {}, h('h3', {}, 'API schema'), h('div', { class: 'stack', style: 'margin-top:8px' }, r.detail.split('; ').map(p => h('div', {}, h('span', { class: 'chip bad' }, p.split(':')[0]), ' ', h('span', { class: 'muted' }, p.slice(p.indexOf(':') + 1))))));
}
function exemptFormFill(form, ev, detector) {
  const prefix = h('input', { value: ev.path, 'aria-label': 'Path prefix' }), det = h('select', { 'aria-label': 'Detector' }, ['rules', 'payload ML', 'behavior', 'schema'].map(d => h('option', { value: d, selected: d === detector }, d)));
  const names = [...new URLSearchParams(ev.query).keys()], param = h('input', { value: names[0] || '', placeholder: 'any parameter', 'aria-label': 'Parameter' });
  const out = h('div', {});
  const cand = () => ({ prefix: prefix.value.trim(), param: param.value.trim(), detector: det.value, note: 'from event ' + ev.id });
  form.append(h('p', { class: 'muted' }, 'Silence one detector for one path (and parameter). It is tested against stored traffic and known attacks before it is applied.'),
    h('div', { class: 'row' }, prefix, param, det), out,
    h('div', { class: 'row' }, h('button', { class: 'btn', onclick: async () => { const cur = (await gw('/exemptions')).exemptions; out.replaceChildren(simSummary(await act(() => api('/simulate', { body: { exemptions: [...cur, cand()] } })))); } }, 'Test'),
      h('button', { class: 'btn primary', onclick: async () => { await act(() => api('/apply', { body: { exemptions: [cand()] } }), 'Exemption created'); form.hidden = true; } }, 'Create')));
}
function simSummary(s) {
  const c = s.corpus, st = s.stored;
  return h('div', { class: 'stack' }, h('div', { class: 'row' },
    h('span', { class: 'chip' }, `${st.newly_allowed} stored events become allowed`), h('span', { class: 'chip' }, `${st.newly_flagged} become flagged`),
    h('span', { class: 'chip ' + (c.attacks_caught_after < c.attacks_caught_before ? 'bad' : 'good') }, `attack corpus ${c.attacks_caught_before}→${c.attacks_caught_after} of ${c.attacks}`),
    h('span', { class: 'chip ' + (c.false_alarms_after > c.false_alarms_before ? 'warn' : '') }, `look-alike false alarms ${c.false_alarms_before}→${c.false_alarms_after}`)),
    s.safe ? h('span', { class: 'chip good' }, 'Safe: no known attack would be lost') : h('div', { class: 'chip bad', style: 'white-space:normal' }, 'Blocked: ' + s.blocked_because.join('; ')));
}

/* ---- views -------------------------------------------------------------------------------------- */
const views = {}; let cleanup = null, badge = 0;
const NAV = [['overview', 'Overview'], ['events', 'Events'], ['inbox', 'Learning Inbox'], ['policies', 'Policies'], ['simulator', 'Simulator'], ['apisec', 'API Security'], ['threats', 'Threats'], ['alerts', 'Alerts'], ['settings', 'Settings'], ['evaluation', 'Evaluation']];

views.overview = async root => {
  let win = +(localStorage.win || 3600), live = true, lastId = 0, timer;
  const kpis = h('div', { class: 'grid kpis' }), chart = h('div', { class: 'card' }), reasons = h('div', { class: 'card' }), paths = h('div', { class: 'card' }), sus = h('div', { class: 'card' }), feed = h('div', { class: 'feed' });
  const modeBox = h('span', {}); const winSel = h('select', { 'aria-label': 'Time window', onchange: e => { win = +e.target.value; localStorage.win = win; load(); } }, [[900, 'Last 15 min'], [3600, 'Last hour'], [86400, 'Last 24 h'], [604800, 'Last 7 days']].map(([v, l]) => h('option', { value: v, selected: v === win }, l)));
  const liveBtn = h('button', { class: 'btn sm', onclick: () => { live = !live; liveBtn.textContent = live ? 'Pause' : 'Resume'; } }, 'Pause');
  async function load() {
    const o = await api('/overview?since=' + win), s = o.stats, ba = s.by_action, flagged = (ba.blocked || 0) + (ba.would_block || 0);
    kpis.replaceChildren(...[['Requests', s.total], ['Flagged', s.total ? pct(flagged / s.total) : '0%'], ['Blocked', ba.blocked || 0], ['Would block', ba.would_block || 0], ['Added latency p95', (+s.latency_ms.p95).toFixed(1) + ' ms'], ['Mean risk', s.avg_risk]].map(([k, v]) => h('div', { class: 'card kpi' }, h('b', {}, v), h('span', {}, k))));
    modeBox.replaceChildren(h('div', { class: 'seg', role: 'group', 'aria-label': 'Mode' }, ['monitor', 'block'].map(m => h('button', { 'aria-pressed': s.mode === m, onclick: () => setMode(m, s) }, m === 'monitor' ? 'Monitor' : 'Block'))));
    chart.replaceChildren(h('h2', {}, 'Traffic'), s.timeline.length ? timeline(s.timeline) : empty('No traffic in this window. Send some through the gateway.'));
    reasons.replaceChildren(h('h2', {}, 'Top reasons'), o.top_reasons.length ? h('div', { class: 'stack' }, o.top_reasons.map(([k, n]) => h('div', {}, h('div', { class: 'row' }, h('span', {}, k), h('span', { class: 'grow' }), h('b', {}, n)), bar(n / o.top_reasons[0][1])))) : empty('No flagged requests'));
    paths.replaceChildren(h('h2', {}, 'Most flagged paths'), table(['Path', 'Requests', 'Flagged'], s.top_paths.map(p => ({ cells: [h('span', { class: 'mono' }, p.path), p.requests, p.flagged || 0] }))));
    sus.replaceChildren(h('h2', {}, 'Possible false positives'), o.suspects.length ? h('div', { class: 'stack' }, o.suspects.map(x => h('div', { class: 'row' }, h('div', { class: 'grow' }, h('span', { class: 'mono' }, x.path), h('div', { class: 'muted' }, `${x.count} flags from ${x.ips} clients, only “${x.detector}” fired, mean risk ${x.avg_risk}`)), h('button', { class: 'btn sm', onclick: () => openEvent(x.example, load) }, 'Inspect')))) : h('p', { class: 'muted' }, 'Nothing suspicious. Flags that come from a single detector on many clients show up here.'));
  }
  async function setMode(m, s) {
    if (m === s.mode) return;
    if (m === 'block' && !await ask('Switch to Block mode?', `Attacks will get a 403 and never reach your application. In the last hour ${s.by_action.would_block || 0} request(s) would have been blocked. Check the Learning Inbox for false positives first.`, 'Block')) return;
    await act(() => gw('/mode', { body: { mode: m } }), 'Mode: ' + m); load();
  }
  async function poll() {
    if (!live || document.hidden) return;
    const evs = (await gw('/events?limit=15')).events, fresh = evs.filter(e => e.id > lastId);
    if (!fresh.length) return;
    for (const e of fresh.reverse()) feed.prepend(feedRow(e));
    lastId = Math.max(lastId, ...evs.map(e => e.id)); while (feed.children.length > 30) feed.lastChild.remove();
  }
  const feedRow = e => press(h('div', { class: 'click', role: 'button', style: 'cursor:pointer', onclick: () => openEvent(e.id, load) }, riskChip(e.risk, .5), h('span', { class: 'mono', style: 'word-break:break-all' }, `${e.method} ${e.path}${e.query ? '?' + e.query.slice(0, 80) : ''}`), h('span', { class: 'muted' }, actionChip(e.action))), () => openEvent(e.id, load));
  root.append(h('div', { class: 'stack page' }, h('div', { class: 'row' }, winSel, modeBox, h('span', { class: 'grow' }), h('span', { class: 'badge-live' }, h('i'), 'Live'), liveBtn), kpis, chart,
    h('div', { class: 'grid g2' }, reasons, sus), h('div', { class: 'grid g2' }, paths, h('div', { class: 'card' }, h('h2', {}, 'Live feed'), feed))));
  await load(); await poll();
  if (!root.isConnected) return;                          // the user already navigated elsewhere
  timer = setInterval(() => poll().catch(() => {}), 2000); const t2 = setInterval(() => load().catch(() => {}), 15000);
  cleanup = () => { clearInterval(timer); clearInterval(t2); };
};

views.events = async root => {
  const f = { action: '', ip: '', path: '', min_risk: 0 }; let rows = [], thr = .5;
  const list = h('div', { class: 'card' }), more = h('button', { class: 'btn', onclick: () => load(true) }, 'Load more');
  const q = () => '?limit=50' + Object.entries(f).filter(([, v]) => v).map(([k, v]) => `&${k}=${encodeURIComponent(v)}`).join('');
  async function load(append) {
    thr = (await gw('/mode')).threshold; const before = append && rows.length ? '&before_id=' + rows[rows.length - 1].id : '';
    const got = (await gw('/events' + q() + before)).events; rows = append ? rows.concat(got) : got; draw(got.length === 50);
  }
  const draw = hasMore => list.replaceChildren(table(['Time', 'Risk', 'Action', 'Request', 'Client', 'Why'], rows.map(e => ({ id: e.id, cells: [h('span', { class: 'muted nw' }, clock(e.ts)), riskChip(e.risk, thr), actionChip(e.action), h('span', { class: 'mono' }, `${e.method} ${e.path}${e.query ? '?' + e.query.slice(0, 70) : ''}`), h('span', { class: 'mono' }, e.client_ip), Object.keys(e.detectors).filter(d => e.detectors[d] > 0).map(d => h('span', { class: 'chip' }, d))] })), r => openEvent(r.id, () => load()), 'No events match. Send traffic through the gateway (or run: python -m traffic.replay), or relax the filters.'), hasMore ? h('div', { class: 'row end', style: 'margin-top:12px' }, more) : null);
  const ctl = (el, key) => { el.addEventListener('input', () => { f[key] = el.value; clearTimeout(ctl.t); ctl.t = setTimeout(() => load().catch(e => toast(e.message)), 250); }); return el; };
  root.append(h('div', { class: 'stack page' }, h('div', { class: 'row' },
    ctl(h('select', { 'aria-label': 'Action' }, [['', 'All actions'], ['allowed', 'Allowed'], ['blocked', 'Blocked'], ['would_block', 'Would block']].map(([v, l]) => h('option', { value: v }, l))), 'action'),
    ctl(h('input', { placeholder: 'Client IP', 'aria-label': 'Client IP' }), 'ip'), ctl(h('input', { placeholder: 'Path contains', 'aria-label': 'Path' }), 'path'),
    h('label', { class: 'row muted' }, 'Min risk', ctl(h('input', { type: 'range', min: 0, max: 1, step: .05, value: 0, 'aria-label': 'Minimum risk' }), 'min_risk'))), list));
  await load();
};

views.inbox = async root => {
  const box = h('div', { class: 'stack' }), dismissed = new Set(JSON.parse(localStorage.dismissed || '[]'));
  const key = s => `${s.prefix}|${s.param}|${s.detector}`;
  async function load() {
    const { items } = await api('/inbox'), shown = items.filter(i => !dismissed.has(key(i.suggestion)));
    setBadge(shown.length);
    box.replaceChildren(...(shown.length ? shown.map(card) : [h('div', { class: 'card' }, empty('Inbox zero. Mark events as “Not an attack” and repeated low-confidence flags will show up here as suggested exemptions.'))]));
  }
  const card = i => h('div', { class: 'card stack' }, h('div', { class: 'row' }, h('h2', { class: 'grow' }, `${i.suggestion.detector} on ${i.suggestion.prefix}`), i.safe ? h('span', { class: 'chip good' }, 'Safe to apply') : h('span', { class: 'chip bad' }, 'Unsafe')),
    h('p', { class: 'muted', style: 'margin:0' }, `${i.reason}: ${i.events} flagged requests from ${i.ips} clients, mean risk ${i.avg_risk}${i.suggestion.param ? ', parameter “' + i.suggestion.param + '”' : ''}.`),
    h('div', { class: 'row' }, h('span', { class: 'chip' }, `would allow ${i.would_allow} stored events`), h('span', { class: 'chip ' + (i.corpus.attacks_caught_after < i.corpus.attacks_caught_before ? 'bad' : 'good') }, `known attacks still caught ${i.corpus.attacks_caught_after}/${i.corpus.attacks}`)),
    i.safe ? null : h('div', { class: 'chip bad', style: 'white-space:normal' }, i.blocked_because.join('; ')),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', disabled: !i.safe, onclick: async () => { await act(() => api('/apply', { body: { exemptions: [i.suggestion] } }), 'Exemption applied'); load(); } }, 'Approve'),
      h('button', { class: 'btn', onclick: () => { dismissed.add(key(i.suggestion)); localStorage.dismissed = JSON.stringify([...dismissed]); load(); } }, 'Reject'),
      h('button', { class: 'btn', onclick: () => openEvent(i.example, load) }, 'See an example')));
  root.append(h('div', { class: 'stack page' }, h('p', { class: 'muted', style: 'margin:0;max-width:60ch' }, 'The console proposes narrow exemptions (one detector, one path, one parameter). Each is replayed against your stored traffic and a corpus of known attacks first; an unsafe one cannot be approved.'), box));
  await load();
};

views.policies = async root => {
  const [mode, lists, ex, routes] = await Promise.all([gw('/mode'), gw('/lists'), gw('/exemptions'), gw('/routes')]);
  let m = mode.mode, thr = mode.threshold; const preview = h('div', { class: 'muted' }, 'Move the slider to preview the effect on stored traffic.');
  const val = h('b', {}, thr.toFixed(2)); let t;
  const range = h('input', { type: 'range', min: .1, max: .95, step: .05, value: thr, 'aria-label': 'Threshold', oninput: e => { thr = +e.target.value; val.textContent = thr.toFixed(2); clearTimeout(t); t = setTimeout(run, 200); } });
  async function run() { const s = await api('/simulate', { body: { threshold: thr, exemptions: ex.exemptions } }), st = s.stored; preview.replaceChildren(h('div', { class: 'stack' }, h('div', { class: 'row' }, h('span', { class: 'chip' }, `${st.flagged_before} → ${st.flagged_after} flagged of ${st.events} stored events`), h('span', { class: 'chip ' + (s.corpus.attacks_caught_after < s.corpus.attacks_caught_before ? 'bad' : 'good') }, `known attacks caught ${s.corpus.attacks_caught_after}/${s.corpus.attacks}`), h('span', { class: 'chip' }, `look-alike false alarms ${s.corpus.false_alarms_after}`)), s.safe ? null : h('div', { class: 'chip bad', style: 'white-space:normal' }, s.blocked_because.join('; ')))); return s; }
  const seg = h('div', { class: 'seg' }, ['monitor', 'block'].map(x => h('button', { 'aria-pressed': m === x, onclick: e => { m = x; [...seg.children].forEach(b => b.setAttribute('aria-pressed', b === e.target)); } }, x === 'monitor' ? 'Monitor (log only)' : 'Block')));
  const apply = h('button', { class: 'btn primary', onclick: async () => {
    if (m === 'block' && mode.mode !== 'block' && !await ask('Switch to Block mode?', 'Attacks will get a 403. Make sure the Learning Inbox is clear.', 'Block')) return;
    if (thr !== mode.threshold) await act(() => api('/apply', { body: { threshold: thr } })); if (m !== mode.mode) await act(() => gw('/mode', { body: { mode: m } })); toast('Policy saved'); render(); } }, 'Apply');
  const ipForm = { ip: h('input', { placeholder: '1.2.3.4 or 10.0.0.0/8', 'aria-label': 'IP or range' }), kind: h('select', { 'aria-label': 'List' }, h('option', { value: 'deny' }, 'Deny'), h('option', { value: 'allow' }, 'Allow')), note: h('input', { placeholder: 'Note', 'aria-label': 'Note' }) };
  const routeRows = (routes.routes || []).map(r => ({ ...r })), rbox = h('div', {});
  const drawRoutes = () => rbox.replaceChildren(table(['Path prefix', 'Mode', 'Threshold', 'Inspection', ''], routeRows.map((r, i) => ({ cells: [h('span', { class: 'mono' }, r.prefix), r.mode || 'inherit', r.threshold ?? 'inherit', r.disabled ? 'off' : 'on', h('button', { class: 'btn sm danger', onclick: () => { routeRows.splice(i, 1); drawRoutes(); } }, 'Remove')] }))),
    h('div', { class: 'row', style: 'margin-top:12px' }, rp, rm, rt, h('button', { class: 'btn', onclick: () => { if (!rp.value.startsWith('/')) return toast('Prefix must start with /'); routeRows.push({ prefix: rp.value, mode: rm.value, ...(rt.value ? { threshold: +rt.value } : {}) }); drawRoutes(); } }, 'Add'), h('button', { class: 'btn primary', onclick: () => act(() => gw('/routes', { body: { routes: routeRows } }), 'Routes saved') }, 'Save routes')));
  const rp = h('input', { placeholder: '/admin', 'aria-label': 'Route prefix' }), rm = h('select', { 'aria-label': 'Route mode' }, h('option', { value: 'block' }, 'block'), h('option', { value: 'monitor' }, 'monitor')), rt = h('input', { placeholder: 'threshold', size: 8, 'aria-label': 'Route threshold' });
  drawRoutes();
  root.append(h('div', { class: 'stack page' },
    h('div', { class: 'card stack' }, h('h2', {}, 'Mode and threshold'), seg, h('div', { class: 'row' }, h('span', {}, 'Threshold'), val, range), preview, h('div', { class: 'row' }, apply)),
    h('div', { class: 'card' }, h('h2', {}, 'Per-route overrides'), h('p', { class: 'muted' }, 'The longest matching prefix wins. Example: block everything under /admin even while the rest is in monitor mode.'), rbox),
    h('div', { class: 'card' }, h('h2', {}, 'IP lists'), table(['Address', 'List', 'Note', ''], lists.lists.map(l => ({ cells: [h('span', { class: 'mono' }, l.ip), l.kind, l.note, h('button', { class: 'btn sm danger', onclick: async () => { await act(() => gw('/lists/' + l.ip.replace('/', '_'), { method: 'DELETE' }), 'Removed'); render(); } }, 'Remove')] }))),
      h('div', { class: 'row', style: 'margin-top:12px' }, ipForm.ip, ipForm.kind, ipForm.note, h('button', { class: 'btn', onclick: async () => { await act(() => gw('/lists', { body: { ip: ipForm.ip.value, kind: ipForm.kind.value, note: ipForm.note.value } }), 'Added'); render(); } }, 'Add'))),
    h('div', { class: 'card' }, h('h2', {}, 'Exemptions'), table(['Path prefix', 'Parameter', 'Detector silenced', 'Note', ''], ex.exemptions.map(e => ({ cells: [h('span', { class: 'mono' }, e.prefix), e.param || 'any', e.detector, e.note, h('button', { class: 'btn sm danger', onclick: async () => { await act(() => gw('/exemptions/' + e.id, { method: 'DELETE' }), 'Exemption removed'); render(); } }, 'Remove')] }))))));
};

views.simulator = async root => {
  const cur = await gw('/exemptions'), mode = await gw('/mode'); let thr = mode.threshold, cands = [];
  const out = h('div', {}), val = h('b', {}, thr.toFixed(2)), list = h('div', {});
  const range = h('input', { type: 'range', min: .1, max: .95, step: .05, value: thr, 'aria-label': 'Candidate threshold', oninput: e => { thr = +e.target.value; val.textContent = thr.toFixed(2); } });
  const f = { prefix: h('input', { placeholder: '/products/search', 'aria-label': 'Path prefix' }), param: h('input', { placeholder: 'parameter (optional)', 'aria-label': 'Parameter' }), det: h('select', { 'aria-label': 'Detector' }, ['rules', 'payload ML', 'behavior', 'schema'].map(d => h('option', { value: d }, d))) };
  const drawCands = () => list.replaceChildren(...cands.map((c, i) => h('div', { class: 'row' }, h('span', { class: 'chip' }, `${c.detector} · ${c.prefix}${c.param ? ' · ' + c.param : ''}`), h('button', { class: 'btn sm', onclick: () => { cands.splice(i, 1); drawCands(); } }, 'Remove'))));
  let last;
  async function run() {
    last = await act(() => api('/simulate', { body: { threshold: thr, exemptions: [...cur.exemptions, ...cands] } }));
    const s = last.stored, c = last.corpus;
    out.replaceChildren(h('div', { class: 'grid g2' },
      h('div', { class: 'card stack' }, h('h2', {}, 'Stored traffic'), h('div', { class: 'row' }, h('span', { class: 'kpi' }, h('b', {}, `${s.flagged_before} → ${s.flagged_after}`), h('span', {}, `flagged of ${s.events} events`))),
        h('div', { class: 'row' }, h('span', { class: 'chip' }, `${s.newly_allowed} newly allowed`), h('span', { class: 'chip' }, `${s.newly_flagged} newly flagged`)),
        s.allowed_sample.length ? table(['Newly allowed', 'Risk'], s.allowed_sample.map(e => ({ id: e.id, cells: [h('span', { class: 'mono' }, `${e.method} ${e.path}?${e.query.slice(0, 50)}`), e.risk.toFixed(2)] })), r => openEvent(r.id)) : null),
      h('div', { class: 'card stack' }, h('h2', {}, 'Regression corpus (known attacks and look-alikes)'),
        h('div', { class: 'row' }, h('span', { class: 'kpi' }, h('b', {}, `${c.attacks_caught_before} → ${c.attacks_caught_after}`), h('span', {}, `of ${c.attacks} attacks caught`)), h('span', { class: 'kpi' }, h('b', {}, `${c.false_alarms_before} → ${c.false_alarms_after}`), h('span', {}, `false alarms on ${c.benign} look-alikes`))),
        c.attacks_lost.length ? h('div', { class: 'stack' }, h('span', { class: 'chip bad' }, 'Attacks that would get through'), c.attacks_lost.slice(0, 5).map(a => h('pre', { class: 'req' }, a.text))) : h('span', { class: 'chip good' }, 'No known attack lost'))),
      h('div', { class: 'row' }, last.safe ? h('span', { class: 'chip good' }, 'Safe to apply') : h('span', { class: 'chip bad', style: 'white-space:normal' }, 'Cannot apply: ' + last.blocked_because.join('; ')),
        h('span', { class: 'grow' }), h('button', { class: 'btn primary', disabled: !last.safe || (!cands.length && thr === mode.threshold), onclick: async () => { await act(() => api('/apply', { body: { threshold: thr, exemptions: cands } }), 'Applied'); render(); } }, 'Apply candidate')));
  }
  root.append(h('div', { class: 'stack page' }, h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, 'Try a policy change without touching live traffic. It is replayed against your stored events and a regression corpus. If any known attack would slip through, Apply stays disabled.'),
    h('div', { class: 'card stack' }, h('h2', {}, 'Candidate'), h('div', { class: 'row' }, h('span', {}, 'Threshold'), val, range), h('h3', {}, 'Add exemptions'), h('div', { class: 'row' }, f.prefix, f.param, f.det, h('button', { class: 'btn', onclick: () => { if (!f.prefix.value.startsWith('/')) return toast('Prefix must start with /'); cands.push({ prefix: f.prefix.value, param: f.param.value, detector: f.det.value, note: 'simulator' }); drawCands(); } }, 'Add')), list, h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: run }, 'Run simulation'))), out));
  await run();
};

views.threats = async root => {
  const { rows } = await api('/threats');
  const timelineOf = async ip => {
    const evs = (await gw('/events?limit=200&ip=' + encodeURIComponent(ip))).events.reverse(), thr = (await gw('/mode')).threshold;
    const w = 520, hgt = 70, s = svg('svg', { viewBox: `0 0 ${w} ${hgt}`, style: 'width:100%;height:70px' });
    evs.forEach((e, i) => { const c = svg('circle', { cx: 6 + i * (w - 12) / Math.max(evs.length - 1, 1), cy: hgt - 6 - e.risk * (hgt - 12), r: 3.5, fill: e.risk >= thr ? 'var(--bad)' : 'var(--mute)' }); s.append(c); });
    const denied = (await gw('/lists')).lists.some(l => l.ip === ip && l.kind === 'deny');
    openDrawer(ip, h('div', { class: 'stack' }, h('div', { class: 'row' }, h('span', { class: 'chip' }, `${evs.length} recent requests`), denied ? h('span', { class: 'chip bad' }, 'banned') : h('button', { class: 'btn danger', onclick: async () => { if (await ask('Ban ' + ip + '?', 'All requests from this address will get 403.', 'Ban')) { await act(() => gw('/lists', { body: { ip, kind: 'deny', note: 'banned from Threats' } }), 'Banned'); closeDrawer(); render(); } } }, 'Ban IP')),
      h('div', {}, h('h3', {}, 'Risk over time'), s), h('div', {}, h('h3', {}, 'Story'), evs.slice(-40).reverse().map(e => press(h('div', { class: 'row', role: 'button', style: 'padding:5px 0;border-top:1px solid var(--line);cursor:pointer', onclick: () => openEvent(e.id) }, riskChip(e.risk, thr), h('span', { class: 'muted' }, clock(e.ts)), h('span', { class: 'mono grow', style: 'word-break:break-all' }, `${e.method} ${e.path}`), actionChip(e.action)), () => openEvent(e.id))))));
  };
  root.append(h('div', { class: 'card page' }, h('h2', {}, 'Clients by risk (last 24 h)'), table(['Client', 'Requests', 'Flagged', 'Max risk', 'Main signals', 'Last seen', ''], rows.map(r => ({ ip: r.ip, cells: [h('span', { class: 'mono' }, r.ip), r.requests, r.flagged, h('b', {}, r.max_risk.toFixed(2)), r.top.map(([d, n]) => h('span', { class: 'chip' }, `${d} ×${n}`)), h('span', { class: 'muted' }, ago(r.last_ts)), r.denied ? h('span', { class: 'chip bad' }, 'banned') : ''] })), r => timelineOf(r.ip), 'No clients yet. They appear as soon as traffic goes through the gateway.')));
};

views.apisec = async root => {
  const s = await gw('/schema');
  if (!s.loaded) return root.append(h('div', { class: 'stack page' }, h('div', { class: 'card' }, h('h2', {}, 'No API schema loaded'), h('p', { class: 'muted', style: 'max-width:62ch' }, 'The schema detector flags requests that do not fit the API: unknown endpoints, parameters or methods, missing or mistyped fields, privileged fields such as role. Build one with: python -m wafgw.schema_learn --openapi <url> (or --dataset / --events). The gateway picks the file up by itself within a few seconds, or press the button.'), h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { const r = await act(() => gw('/reload', { method: 'POST' })); toast(r.reloaded.length ? 'Loaded: ' + r.reloaded.join(', ') : 'Nothing new to load'); render(); } }, 'Reload models')))));
  const kinds = Object.entries(s.findings_24h).sort((a, b) => b[1] - a[1]);
  root.append(h('div', { class: 'stack page' },
    h('div', { class: 'card' }, h('h2', {}, 'Schema findings, last 24 h'), kinds.length ? h('div', { class: 'stack' }, kinds.map(([k, n]) => h('div', {}, h('div', { class: 'row' }, h('span', {}, k.replace(/_/g, ' ')), h('span', { class: 'grow' }), h('b', {}, n)), bar(n / kinds[0][1])))) : h('p', { class: 'muted' }, 'No request broke the schema.')),
    h('div', { class: 'card' }, h('h2', {}, `Known endpoints (${s.endpoints.length})`), table(['Endpoint', 'Method', 'Fields (required in bold)'], s.endpoints.flatMap(e => Object.entries(e.methods).map(([m, v]) => ({ cells: [h('span', { class: 'mono' }, e.endpoint), m, h('span', {}, v.open ? h('span', { class: 'chip' }, 'open body') : null, v.params.map(p => h('span', { class: 'chip' }, p.required ? h('b', {}, p.name) : p.name)))] })))))));
};

views.alerts = async root => {
  const cfg = (await gw('/settings/alerts')).value || {}, logBox = h('div', {});
  const f = { enabled: h('input', { type: 'checkbox', checked: !!cfg.enabled, 'aria-label': 'Enabled' }), kind: h('select', { 'aria-label': 'Format' }, ['slack', 'discord', 'generic'].map(k => h('option', { value: k, selected: cfg.kind === k }, k))), url: h('input', { value: cfg.url || '', placeholder: 'https://hooks.example.com/…', size: 44, 'aria-label': 'Webhook URL' }), min: h('input', { type: 'number', min: .1, max: 1, step: .05, value: cfg.min_risk ?? .8, 'aria-label': 'Minimum risk' }), dedup: h('input', { type: 'number', min: 10, step: 10, value: cfg.dedup_s ?? 300, 'aria-label': 'Dedup seconds' }) };
  const value = () => ({ enabled: f.enabled.checked, kind: f.kind.value, url: f.url.value.trim(), min_risk: +f.min.value, dedup_s: +f.dedup.value });
  async function log() { const l = (await api('/alerts/log')).log; logBox.replaceChildren(table(['When', 'Client', 'Path', 'Risk', 'Result'], l.map(a => ({ cells: [ago(a.ts), h('span', { class: 'mono' }, a.ip), h('span', { class: 'mono' }, a.path), a.risk.toFixed(2), a.status] })))); }
  root.append(h('div', { class: 'stack page' }, h('div', { class: 'card stack' }, h('h2', {}, 'Webhook alerts'), h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, 'Sends a message to Slack, Discord or any JSON endpoint when a request reaches the minimum risk. The same client and signal alert at most once per dedup window.'),
    h('label', { class: 'row' }, f.enabled, 'Enabled'), h('div', { class: 'row' }, f.kind, f.url), h('div', { class: 'row' }, h('label', { class: 'row muted' }, 'Minimum risk', f.min), h('label', { class: 'row muted' }, 'Dedup (seconds)', f.dedup)),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: () => act(() => gw('/settings/alerts', { body: value() }), 'Alert settings saved') }, 'Save'), h('button', { class: 'btn', onclick: async () => { await act(() => gw('/settings/alerts', { body: value() })); const r = await act(() => api('/alerts/test', { method: 'POST' })); toast('Test sent: ' + r.status); log(); } }, 'Send test'))),
    h('div', { class: 'card' }, h('h2', {}, 'Recent alerts'), logBox)));
  log();
};

views.settings = async root => {
  const audit = (await gw('/audit?limit=100')).audit, health = await gw('/health'), box = h('textarea', { 'aria-label': 'Policy JSON', spellcheck: 'false' });
  const exportPolicy = async () => { const p = await gw('/policy'); box.value = JSON.stringify(p, null, 2); return p; };
  root.append(h('div', { class: 'stack page' },
    h('div', { class: 'card stack' }, h('h2', {}, 'Policy as code'), h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, 'Export mode, threshold, routes, IP lists, exemptions and alert settings as one JSON file you can review and keep in git. Import replaces the current policy (validated first, so a bad file changes nothing).'), box,
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: exportPolicy }, 'Export to editor'), h('button', { class: 'btn', onclick: async () => { const p = await exportPolicy(); const a = h('a', { href: URL.createObjectURL(new Blob([JSON.stringify(p, null, 2)], { type: 'application/json' })), download: 'aegis-policy.json' }); a.click(); } }, 'Download'),
        h('button', { class: 'btn primary', onclick: async () => { let d; try { d = JSON.parse(box.value); } catch { return toast('That is not valid JSON'); } if (await ask('Replace the current policy?', 'Mode, threshold, routes, lists, exemptions and alert settings will be replaced.', 'Import')) { await act(() => gw('/policy', { body: d }), 'Policy imported'); } } }, 'Import from editor'))),
    h('div', { class: 'card' }, h('h2', {}, 'Gateway'), h('div', { class: 'row' }, h('span', { class: 'chip good' }, `up ${Math.round(health.uptime_s / 60)} min`), h('span', { class: 'chip ' + (health.models.payload ? 'good' : 'warn') }, 'payload model ' + (health.models.payload ? 'loaded' : 'missing')), h('span', { class: 'chip ' + (health.models.behavior ? 'good' : 'warn') }, 'behavior model ' + (health.models.behavior ? 'loaded' : 'missing')), h('span', { class: 'chip ' + (health.models.schema ? 'good' : '') }, 'API schema ' + (health.models.schema ? 'loaded' : 'not loaded')),
      Object.entries(health.reload_errors || {}).map(([f, m]) => h('span', { class: 'chip bad' }, `${f}: ${m}`)), h('span', { class: 'grow' }), h('button', { class: 'btn sm', onclick: async () => { const r = await act(() => gw('/reload', { method: 'POST' })); toast(r.reloaded.length ? 'Loaded: ' + r.reloaded.join(', ') : 'Everything is up to date'); render(); } }, 'Reload models'))),
    h('div', { class: 'card' }, h('h2', {}, 'Audit log'), table(['When', 'Who', 'Change', 'Detail'], audit.map(a => ({ cells: [h('span', { class: 'muted' }, ago(a.ts)), a.actor, h('span', { class: 'mono' }, a.action), h('span', { class: 'mono muted', style: 'word-break:break-all' }, a.detail.slice(0, 120))] }))))));
};

views.evaluation = async root => {
  let thr = .5; const body = h('div', { class: 'stack' }), val = h('b', {}, '0.50'); let t;
  async function load() {
    const s = await api('/eval/summary?threshold=' + thr), names = s.detectors.map(d => d.name);
    body.replaceChildren(h('div', { class: 'card' }, h('h2', {}, 'Detectors on the labeled dataset'), h('p', { class: 'muted' }, `${s.requests} requests, ${s.attacks} attacks (offline evaluation with ground truth, separate from live traffic).`),
      table(['Detector', 'Precision', 'Recall', 'F1', 'Caught', 'Missed', 'False alarms'], s.detectors.map(d => ({ cells: [d.name === 'hybrid' ? h('b', {}, 'hybrid (fused)') : d.name, pct(d.precision), pct(d.recall), pct(d.f1), d.caught, d.missed, d.false_alarms] })))),
      h('div', { class: 'card' }, h('h2', {}, 'Recall by attack type'), table(['Attack', 'Count', ...names], s.by_type.filter(r => r.attack_type !== 'normal').map(r => ({ cells: [r.attack_type, r.attacks, ...names.map(n => h('div', {}, bar(r[n]), pct(r[n])))] })))));
  }
  root.append(h('div', { class: 'stack page' }, h('div', { class: 'row' }, h('span', {}, 'Hybrid threshold'), val, h('input', { type: 'range', min: .1, max: .9, step: .05, value: .5, 'aria-label': 'Threshold', oninput: e => { thr = +e.target.value; val.textContent = thr.toFixed(2); clearTimeout(t); t = setTimeout(load, 150); } })), body));
  await load();
};

/* ---- shell: router, login, boot ----------------------------------------------------------------- */
function setBadge(n) { badge = n; const a = document.querySelector('nav a[href="#/inbox"]'); if (!a) return; a.querySelector('.n')?.remove(); if (n) a.append(h('span', { class: 'n' }, n)); }
const skeleton = () => h('div', { class: 'stack', 'aria-hidden': 'true' }, h('div', { class: 'sk', style: 'height:40px;width:55%' }), h('div', { class: 'grid kpis' }, [0, 1, 2, 3].map(() => h('div', { class: 'sk', style: 'height:84px' }))), h('div', { class: 'sk', style: 'height:220px' }), h('div', { class: 'grid g2' }, h('div', { class: 'sk', style: 'height:160px' }), h('div', { class: 'sk', style: 'height:160px' })));
function errorCard(e) {
  const down = [502, 503, 504].includes(e.status), offline = e instanceof TypeError;
  return h('div', { class: 'card stack page', role: 'alert' }, h('h2', {}, offline ? 'The console server is not answering' : down ? 'Can’t reach the gateway' : 'Something went wrong'),
    h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, offline ? 'Check that “python -m dashboard” is still running.' : e.message),
    down ? h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, 'Start the gateway with “WAF_ADMIN_TOKEN=… python -m wafgw”. This page reconnects by itself.') : null,
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: render }, 'Try again')));
}
let renderId = 0, viewFailed = false, gwOk = true;
async function render() {
  cleanup && cleanup(); cleanup = null;
  const name = (location.hash.match(/^#\/(\w+)/) || [])[1]; const key = views[name] ? name : 'overview';
  document.querySelectorAll('nav a').forEach(a => { if (a.dataset.k === key) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  document.querySelector('nav a[aria-current]')?.scrollIntoView({ inline: 'center', block: 'nearest' });   // phone: keep the current section visible in the scrolling bar
  $('title').textContent = NAV.find(n => n[0] === key)[1]; document.title = NAV.find(n => n[0] === key)[1] + ' · Aegis';
  const view = $('view'), root = h('div', { hidden: true }), mine = ++renderId;
  view.replaceChildren(root); view.setAttribute('aria-busy', 'true'); closeDrawer();
  const skel = skeleton(), late = setTimeout(() => view.prepend(skel), 120);     // only if loading is not instant
  try { await views[key](root); viewFailed = false; }
  catch (e) { if (e.message !== 'login required') { root.replaceChildren(errorCard(e)); viewFailed = true; } }
  clearTimeout(late); skel.remove();
  if (mine === renderId) { root.hidden = false; view.removeAttribute('aria-busy'); }
}
function setGateway(ok, consoleDown = false) {
  $('gwDot').className = 'dot ' + (ok ? 'ok' : 'bad'); $('gwText').textContent = ok ? 'Gateway connected' : consoleDown ? 'Console offline' : 'Gateway unreachable';
  const b = $('banner'); b.hidden = ok;
  if (!ok) b.textContent = consoleDown ? 'The console server is not answering. Retrying every 8 seconds.' : 'The gateway is unreachable, so what you see may be out of date. Retrying every 8 seconds.';
  if (ok && !gwOk) { toast('Reconnected'); if (viewFailed) render(); }
  gwOk = ok;
}
setInterval(async () => {
  if ($('app').hidden) return;
  try { const s = await fetch('/api/session').then(r => r.json()); if (s.logged_in) setGateway(s.gateway_ok); } catch { setGateway(false, true); }
}, 8000);
function showLogin() { $('app').hidden = true; $('login').hidden = false; $('pw').focus(); }
$('loginForm').onsubmit = async e => { e.preventDefault(); try { await api('/login', { body: { password: $('pw').value } }); $('login').hidden = true; boot(); } catch (x) { $('loginErr').textContent = x.message; } };
async function boot() {
  const s = await fetch('/api/session').then(r => r.json());
  if (!s.logged_in) return showLogin();
  $('login').hidden = true; $('app').hidden = false;
  $('nav').replaceChildren(...NAV.map(([k, l]) => h('a', { href: '#/' + k, 'data-k': k }, l)));
  setGateway(s.gateway_ok);
  if (s.auth_required) $('topRight').replaceChildren(h('button', { class: 'btn sm', onclick: async () => { await api('/logout', { method: 'POST' }); location.reload(); } }, 'Sign out'));
  render(); api('/inbox').then(i => setBadge(i.items.length)).catch(() => {});
}
addEventListener('hashchange', render); boot();
