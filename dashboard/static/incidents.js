'use strict';
/* Incidents and Reports pages. Loaded after app.js and uses its helpers (h, api, gw, act, toast, ask, press, table, bar,
   segmented, openDrawer, openEvent, setModeFromPalette, ago, clock, dayClock, icon). Text from traffic goes through h() only. */
ICONS.incidents = 'M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z';
ICONS.reports = 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8M8 17h5';
NAV.splice(Math.max(0, NAV.findIndex(n => n[0] === 'inbox') + 1), 0, ['incidents', 'Incidents', 'incidents', 'n']);
NAV.splice(NAV.findIndex(n => n[0] === 'alerts') + 1 || NAV.length, 0, ['reports', 'Reports', 'reports', 'r']);

const sevChip = s => h('span', { class: 'chip sev sev-' + s }, s);
const OUTCOME = { possibly_succeeded: ['bad', 'May have succeeded'], blocked: ['good', 'Blocked'], failed: ['', 'Likely failed'], unknown: ['', 'No impact signal'] };
const outcomeChip = o => { const [c, t] = OUTCOME[o.level] || ['', o.level]; return h('span', { class: 'chip ' + c, title: o.detail }, t); };
const REF_LABEL = { owasp_api: 'OWASP API', owasp_top10: 'OWASP Top 10', cwe: 'CWE', attack: 'MITRE ATT&CK' };
const refList = refs => h('dl', { class: 'refs' }, Object.entries(refs).flatMap(([k, vals]) => [h('dt', {}, REF_LABEL[k] || k), h('dd', {}, [].concat(vals).join(' · '))]));
const span = s => s < 1 ? 'a moment' : s < 90 ? Math.round(s) + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : (s / 3600).toFixed(1) + ' h';
const download = (name, text, type) => { const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name }); document.body.append(a); a.click(); a.remove(); };
let explainerCache;
const explainerOn = async () => (explainerCache ||= gw('/explainer').catch(() => ({ enabled: false })));

/* ---- one incident, as a story in the drawer ------------------------------------------------------------- */
async function openIncident(id) {
  const i = await act(() => gw('/incidents/' + id)), ex = await explainerOn();
  const statusText = st => Object.entries(st).map(([c, n]) => (c === 'none' ? 'no response' : c) + (n > 1 ? ' ×' + n : '')).join(', ');
  const aiBox = h('div', { class: 'stack' });
  const aiButton = h('button', { class: 'btn', onclick: async () => {
    aiButton.disabled = true; aiButton.textContent = 'Asking…';
    try { const r = await gw(`/incidents/${id}/narrative`, { method: 'POST' }); aiBox.replaceChildren(h('p', {}, r.text), h('span', { class: 'ai-note' }, `AI-written by ${r.model} from the facts above. ${r.note}`)); aiButton.remove(); }
    catch (e) { toast(e.message); aiButton.disabled = false; aiButton.textContent = 'Explain with AI'; }
  } }, 'Explain with AI');
  const actions = i.actions.map(a => a.type === 'ban'
    ? h('button', { class: 'btn danger', onclick: async () => { await act(() => gw('/lists', { body: { ip: a.ip, kind: 'deny', note: 'banned from incident ' + id } })); toast('Banned ' + a.ip, { undo: () => act(() => gw('/lists/' + a.ip.replace('/', '_'), { method: 'DELETE' }), 'Ban removed') }); } }, icon('ban', 14), a.label)
    : a.type === 'block_mode' ? h('button', { class: 'btn primary', onclick: () => setModeFromPalette('block') }, a.label)
    : h('button', { class: 'btn', onclick: () => openEvent(a.event_id) }, a.label));
  const step = s => {
    if (s.more) return h('li', { class: 'muted', style: 'padding:8px 0' }, `…and ${s.more} more steps`);
    const li = h('li', { class: 'tl-step ' + (s.max_risk >= .75 ? 'bad' : s.max_risk >= .4 ? 'warn' : ''), role: 'button', onclick: () => openEvent(s.event_id) },
      h('div', { class: 'tl-time' }, clock(s.ts) + (s.end_ts - s.ts >= 1 ? ' – ' + clock(s.end_ts) : '') + (s.count > 1 ? ` · ${s.count} requests` : '')),
      h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: 'mono' }, `${s.method} ${s.path}`), s.classes.map(c => h('span', { class: 'chip' }, (i.classes.find(x => x.key === c) || { name: c }).name)),
        Object.entries(s.statuses).map(([c, n]) => h('span', { class: 'chip ' + (+c >= 500 ? 'warn' : '') }, (+c || 'blocked') + (n > 1 ? ' ×' + n : '')))),
      s.evidence ? h('div', { class: 'tl-ev mono' }, s.evidence) : null);
    return press(li, () => openEvent(s.event_id));
  };
  openDrawer(`Incident · ${i.client_ip}`, h('div', { class: 'stack' },
    h('div', { class: 'row' }, sevChip(i.severity), h('span', { class: 'chip' }, `${i.confidence} confidence`), outcomeChip(i.outcome), h('span', { class: 'muted' }, `${dayClock(i.first_ts)} · ${span(i.duration_s)}`)),
    h('div', { class: 'callout ' + (i.outcome.level === 'possibly_succeeded' ? 'bad' : i.outcome.level === 'blocked' ? 'good' : '') }, h('b', {}, OUTCOME[i.outcome.level]?.[1] || i.outcome.level), ' — ', i.outcome.detail),
    h('div', { class: 'sec story' }, h('h3', {}, 'What happened'), i.narrative.map(p => h('p', {}, p)), h('span', { class: 'muted ai-note' }, `Rule-based write-up from ${i.events} flagged request${i.events === 1 ? '' : 's'}; statuses: ${statusText(i.statuses)}.`)),
    h('div', { class: 'sec' }, h('h3', {}, 'Timeline'), h('ol', { class: 'tl' }, i.timeline.map(step))),
    Object.keys(i.refs).length ? h('div', { class: 'sec' }, h('h3', {}, 'References'), refList(i.refs)) : null,
    h('div', { class: 'sec' }, h('h3', {}, 'What to do'), h('ol', { class: 'rec-list' }, i.recommendations.map(r => h('li', {}, r))), h('div', { class: 'row' }, actions)),
    h('div', { class: 'sec' }, h('h3', {}, 'AI explanation'),
      ex.enabled ? [aiBox, h('div', { class: 'row' }, aiButton), h('span', { class: 'ai-note' }, `Sends only computed facts (no request bodies, no full IP) to ${ex.endpoint_host}.`)]
        : h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, 'Optional and off. Enable [explainer] in waf.toml to add a short AI-written summary here; only computed facts would be sent, never request bodies.'))));
}

/* ---- Incidents page ---------------------------------------------------------------------------------------- */
views.incidents = async root => {
  let win = +(localStorage.incWin || 86400), sev = 'all', query = '', all = [], shown = 60;
  const list = h('div', { class: 'inc-list' }), summary = h('div', { class: 'sev-filter', role: 'group', 'aria-label': 'Filter by severity' }), count = h('span', { class: 'muted' });
  const search = h('input', { type: 'search', placeholder: 'Filter by IP or technique', 'aria-label': 'Filter incidents', oninput: e => { query = e.target.value.trim().toLowerCase(); shown = 60; paint(); } });
  const winSeg = segmented([[3600, '1 hour'], [86400, '24 hours'], [604800, '7 days']], win, v => { win = +v; localStorage.incWin = win; load(); }, 'Time window');
  const row = i => press(h('div', { class: 'inc-row', role: 'button', onclick: () => openIncident(i.id) },
    sevChip(i.severity),
    h('div', {}, h('div', { class: 'inc-title' }, i.summary), h('div', { class: 'inc-meta muted' }, `${ago(i.last_ts)} · ${span(i.duration_s)} · ${i.events} flagged · ${i.confidence} confidence · ${Object.keys(i.detectors).join(', ') || 'fused score'}`),
      h('div', {}, i.classes.map(c => h('span', { class: 'chip wrap-text' }, c.name)))),
    h('div', { class: 'inc-side' }, h('span', { class: 'inc-risk' }, i.max_risk.toFixed(2)), outcomeChip(i.outcome))), () => openIncident(i.id));
  function paint() {
    const counts = { all: all.length, critical: 0, high: 0, medium: 0, low: 0 }; all.forEach(i => counts[i.severity]++);
    summary.replaceChildren(...['all', 'critical', 'high', 'medium', 'low'].map(s => h('button', { type: 'button', 'aria-pressed': String(sev === s), onclick: () => { sev = s; shown = 60; paint(); } }, `${s === 'all' ? 'All' : s[0].toUpperCase() + s.slice(1)} ${counts[s]}`)));
    const rows = all.filter(i => (sev === 'all' || i.severity === sev) && (!query || i.client_ip.includes(query) || i.summary.toLowerCase().includes(query)));
    count.textContent = rows.length ? `${rows.length} incident${rows.length === 1 ? '' : 's'}` : '';
    list.replaceChildren(...(rows.length ? rows.slice(0, shown).map(row) : [empty(all.length ? 'Nothing matches this filter.' : 'Nothing was flagged in this window. When something is, it appears here as one story per client, with what happened, whether it worked, and what to do.', all.length ? 'No matches' : 'No incidents')]),
      rows.length > shown ? h('button', { class: 'btn', onclick: () => { shown += 60; paint(); } }, `Show ${Math.min(60, rows.length - shown)} more`) : null);
  }
  async function load() {
    list.setAttribute('aria-busy', 'true');
    all = (await act(() => gw(`/incidents?since=${Date.now() / 1000 - win}&limit=300`))).incidents;
    list.removeAttribute('aria-busy'); paint();
  }
  root.append(h('div', { class: 'stack page' },
    h('div', { class: 'card stack' }, h('div', { class: 'inc-tools' }, winSeg, search, count), summary,
      h('p', { class: 'muted', style: 'margin:0;max-width:68ch' }, 'Flagged requests from the same client are grouped into one incident. Each one is written up in plain language, mapped to OWASP, CWE and MITRE ATT&CK, and says whether the application seems to have been affected.')),
    list));
  await load();
};

/* ---- Reports page ---------------------------------------------------------------------------------------------- */
views.reports = async root => {
  let hours = +(localStorage.repHours || 24);
  const preview = h('div', { class: 'stack' }), saved = h('div', {}), sched = h('div', { class: 'stack' });
  const q = () => `window_h=${hours}`;
  const hoursSeg = segmented([[24, '24 hours'], [168, '7 days'], [720, '30 days']], hours, v => { hours = +v; localStorage.repHours = hours; preview.replaceChildren(); }, 'Report window');
  const busy = (btn, fn) => async () => { btn.disabled = true; try { await fn(); } finally { btn.disabled = false; } };
  const paintPreview = r => {
    const s = r.summary, kp = (v, l) => h('div', {}, h('b', {}, v), h('span', {}, l));
    preview.replaceChildren(
      h('p', { style: 'margin:0;max-width:68ch;font-size:1.0625rem;letter-spacing:-.01em' }, s.headline),
      h('div', { class: 'rep-kpis' }, kp(s.requests.toLocaleString(), 'requests'), kp(s.flagged.toLocaleString(), 'flagged'), kp(s.blocked.toLocaleString(), 'blocked'), kp(s.incidents, 'incidents'), kp(s.succeeded, 'may have succeeded')),
      h('div', { class: 'row' }, Object.entries(s.by_severity).filter(([, n]) => n).map(([k, n]) => h('span', { class: 'chip sev sev-' + k }, `${n} ${k}`))),
      r.attack_types.length ? h('div', { class: 'stack' }, h('h3', {}, 'Attack types'), r.attack_types.slice(0, 6).map(k => h('div', {}, h('div', { class: 'row' }, h('span', {}, k.name), h('span', { class: 'grow' }), h('b', {}, k.events.toLocaleString())), bar(k.events / r.attack_types[0].events)))) : null,
      r.incidents.length ? h('div', { class: 'stack' }, h('h3', {}, 'Notable incidents'), h('div', { class: 'inc-list' }, r.incidents.slice(0, 3).map(i => press(h('div', { class: 'inc-row', role: 'button', onclick: () => openIncident(i.id) }, sevChip(i.severity), h('div', {}, h('div', { class: 'inc-title' }, i.summary), h('div', { class: 'inc-meta muted' }, `${dayClock(i.first_ts)} · ${i.events} flagged`)), h('div', { class: 'inc-side' }, outcomeChip(i.outcome))), () => openIncident(i.id))))) : null,
      h('div', { class: 'stack' }, h('h3', {}, 'Recommendations'), h('ol', { class: 'rec-list' }, r.recommendations.slice(0, 6).map(x => h('li', {}, h('span', { class: 'chip' }, x.priority), x.text)))));
  };
  const previewBtn = h('button', { class: 'btn primary' }, 'Preview');
  previewBtn.onclick = busy(previewBtn, async () => { preview.replaceChildren(h('div', { class: 'sk', style: 'height:160px' })); paintPreview(await act(() => gw('/report?' + q()))); });
  const saveBtn = h('button', { class: 'btn' }, 'Save on the gateway');
  saveBtn.onclick = busy(saveBtn, async () => { const r = await act(() => gw('/reports', { method: 'POST' })); toast('Saved: ' + r.path.split('/').pop() + (r.delivery.startsWith('HTTP') ? ' · sent to webhook' : '')); loadSaved(); });
  const htmlBtn = h('button', { class: 'btn' }, icon('copy', 14), 'Download HTML');
  htmlBtn.onclick = busy(htmlBtn, async () => { const r = await fetch(`/api/report-html?${q()}&download=1`); if (!r.ok) return toast('Could not build the report'); download('aegis-report.html', await r.text(), 'text/html'); });
  const jsonBtn = h('button', { class: 'btn' }, 'Download JSON');
  jsonBtn.onclick = busy(jsonBtn, async () => download('aegis-report.json', JSON.stringify(await act(() => gw('/report?' + q())), null, 2), 'application/json'));
  async function loadSaved() {
    const r = await gw('/reports');
    saved.replaceChildren(table(['Report', 'Size', 'Created', ''], r.files.map(f => ({ cells: [h('span', { class: 'mono' }, f.name), Math.max(1, Math.round(f.bytes / 1024)) + ' KB', h('span', { class: 'muted' }, ago(f.ts)), h('a', { class: 'btn sm', href: '/api/report-file/' + encodeURIComponent(f.name), target: '_blank', rel: 'noopener' }, 'Open')] })), null, 'No saved reports yet. Save one above, or enable the schedule.'));
    const s = r.schedule;
    sched.replaceChildren(h('div', { class: 'row' }, h('span', { class: 'chip ' + (s.enabled ? 'good' : '') }, s.enabled ? `Scheduled every ${s.every_h} h` : 'Schedule is off'), h('span', { class: 'chip' }, `window ${s.window_h} h`), h('span', { class: 'chip' }, s.webhook ? 'sent to webhook' : 'no webhook')),
      h('p', { class: 'muted', style: 'margin:0;max-width:62ch' }, 'Scheduled reports are written to ', h('span', { class: 'mono' }, r.dir), '. Turn them on in waf.toml and restart the gateway:'),
      h('div', { class: 'cmd' }, h('code', {}, '[reports]\nenabled = true\nevery_h = 24\nwebhook = true   # also send a summary to Alerts'), h('button', { class: 'icon-btn', style: 'width:28px;height:28px', 'aria-label': 'Copy', onclick: () => navigator.clipboard?.writeText('[reports]\nenabled = true\nevery_h = 24\nwebhook = true').then(() => toast('Copied')) }, icon('copy', 14))));
  }
  root.append(h('div', { class: 'stack page' },
    h('div', { class: 'card stack' }, h('h2', {}, 'Security report'), h('p', { class: 'muted', style: 'margin:0;max-width:68ch' }, 'Executive summary, traffic, attack types mapped to OWASP, notable incidents with timelines, false-positive review, detector agreement and recommendations. Open the HTML and use Print → Save as PDF for a PDF.'),
      h('div', { class: 'row' }, hoursSeg), h('div', { class: 'rep-actions' }, previewBtn, h('a', { class: 'btn', href: `/api/report-html?${q()}`, target: '_blank', rel: 'noopener', onclick: e => { e.currentTarget.href = `/api/report-html?${q()}`; } }, 'Open'), htmlBtn, jsonBtn, saveBtn), preview),
    h('div', { class: 'card stack' }, h('h2', {}, 'Saved reports'), saved),
    h('div', { class: 'card stack' }, h('h2', {}, 'Schedule'), sched)));
  await loadSaved();
};
