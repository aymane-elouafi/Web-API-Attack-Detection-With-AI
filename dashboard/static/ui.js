'use strict';
/* Aegis UI kit: DOM helpers, springs, icons, charts, sheet (drawer), toasts, command palette, theme.
   Dependency-free. Text from traffic always goes through textContent (h()), never innerHTML. */

/* ---- DOM helpers ---------------------------------------------------------------------------------- */
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
const svg = (tag, attrs = {}, ...kids) => {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  e.append(...kids); return e;
};
const prefersReduced = matchMedia('(prefers-reduced-motion: reduce)');

/* ---- springs ---------------------------------------------------------------------------------------
   response = seconds to (nearly) arrive, damping = 1 means no overshoot (below 1 bounces).
   A spring has no fixed duration: retarget() changes the destination mid-flight and the motion stays
   continuous because position AND velocity carry over. Reduced motion jumps straight to the target. */
function spring({ from, to, velocity = 0, response = .4, damping = 1, eps = .01, onUpdate, onDone }) {
  const ctl = { value: from, velocity, target: to, running: false };
  onUpdate(from, velocity);
  if (prefersReduced.matches) { ctl.value = to; ctl.velocity = 0; onUpdate(to, 0); onDone && onDone(); ctl.stop = () => {}; ctl.retarget = t => { ctl.value = ctl.target = t; onUpdate(t, 0); }; return ctl; }
  const k = (2 * Math.PI / response) ** 2, c = 2 * damping * Math.sqrt(k);
  let raf = 0, last = 0;
  const tick = now => {
    const dt = Math.min((now - last) / 1000, .05); last = now;
    const n = Math.max(1, Math.ceil(dt * 240)), step = dt / n;           // 240 Hz sub-steps keep stiff springs stable
    for (let i = 0; i < n; i++) { ctl.velocity += (-k * (ctl.value - ctl.target) - c * ctl.velocity) * step; ctl.value += ctl.velocity * step; }
    if (Math.abs(ctl.value - ctl.target) < eps && Math.abs(ctl.velocity) < eps * 4) {
      ctl.value = ctl.target; ctl.velocity = 0; ctl.running = false; onUpdate(ctl.value, 0); onDone && onDone(); return;
    }
    onUpdate(ctl.value, ctl.velocity); raf = requestAnimationFrame(tick);
  };
  ctl.stop = () => { cancelAnimationFrame(raf); ctl.running = false; };
  ctl.retarget = (t, v = ctl.velocity) => { ctl.target = t; ctl.velocity = v; if (!ctl.running) { ctl.running = true; last = performance.now(); raf = requestAnimationFrame(tick); } };
  ctl.running = true; last = performance.now(); raf = requestAnimationFrame(tick);
  return ctl;
}
/* Where a flick at `velocity` px/s would come to rest (exponential deceleration, as scroll views do). */
const project = (velocity, rate = .998) => (velocity / 1000) * rate / (1 - rate);
/* Progressive resistance past a bound: the further you pull, the less it follows. */
const rubberband = (over, dim, c = .55) => (over * dim * c) / (dim + c * Math.abs(over));
/* Appear: slide up a few px and fade in, from wherever it is. */
function springIn(el, dy = 10) {
  el.style.opacity = '0'; el.style.transform = `translateY(${dy}px)`;
  spring({ from: 0, to: 1, response: .45, eps: .002, onUpdate: x => { el.style.opacity = String(Math.min(1, x)); el.style.transform = `translateY(${(1 - x) * dy}px)`; },
    onDone: () => { el.style.opacity = ''; el.style.transform = ''; } });
}
/* Numbers glide to their new value instead of jumping. */
function countTo(el, value, fmt = v => String(Math.round(v))) {
  const from = el._n ?? value; el._n = value;
  if (from === value) { el.textContent = fmt(value); return; }
  el._sp && el._sp.stop();
  el._sp = spring({ from, to: value, response: .6, eps: Math.max(Math.abs(value - from) * .002, 1e-6), onUpdate: v => { el.textContent = fmt(v); }, onDone: () => { el.textContent = fmt(value); } });
}

/* ---- icons (24px grid, 1.75 stroke) --------------------------------------------------------------- */
const ICONS = {
  overview: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  events: 'M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  policies: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  simulator: 'M9 3h6M10 3v6.5L4.5 19a2 2 0 0 0 1.7 3h11.6a2 2 0 0 0 1.7-3L14 9.5V3',
  apisec: 'M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5zM9 12l2 2 4-4',
  threats: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 2v4M12 18v4M2 12h4M18 12h4',
  alerts: 'M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  evaluation: 'M18 20V10M12 20V4M6 20v-6',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35',
  close: 'M18 6L6 18M6 6l12 12',
  ban: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM4.9 4.9l14.2 14.2',
  check: 'M20 6L9 17l-5-5',
  more: 'M5 12h.01M12 12h.01M19 12h.01',
  up: 'M12 19V5M5 12l7-7 7 7',
  down: 'M12 5v14M19 12l-7 7-7-7',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  copy: 'M9 9h11v11H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1',
  pause: 'M8 5v14M16 5v14',
  play: 'M7 4l13 8-13 8z',
  shield: 'M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z',
};
const icon = (name, size = 18) => svg('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.75, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', class: 'ico' }, svg('path', { d: ICONS[name] || ICONS.more }));

/* ---- charts --------------------------------------------------------------------------------------- */
const clock = ts => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const dayClock = ts => new Date(ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
/* Fill minute gaps and merge into at most `max` buckets so a 7-day window stays readable. */
function bucketize(points, max = 90) {
  if (!points.length) return [];
  const t0 = points[0].t, t1 = points[points.length - 1].t, span = Math.max(60, t1 - t0 + 60);
  const size = Math.max(60, Math.ceil(span / max / 60) * 60), n = Math.floor((t1 - t0) / size) + 1, out = [];
  for (let i = 0; i < n; i++) out.push({ t: t0 + i * size, requests: 0, flagged: 0 });
  for (const p of points) { const b = out[Math.floor((p.t - t0) / size)]; b.requests += p.requests; b.flagged += p.flagged || 0; }
  return out;
}
/* Monotone cubic interpolation (Fritsch-Carlson): smooth, never overshoots the data. */
function smoothPath(pts) {
  const n = pts.length; if (n < 2) return pts.length ? `M${pts[0][0]},${pts[0][1]}` : '';
  const dx = [], m = [], tan = new Array(n);
  for (let i = 0; i < n - 1; i++) { dx.push(pts[i + 1][0] - pts[i][0]); m.push((pts[i + 1][1] - pts[i][1]) / (dx[i] || 1)); }
  tan[0] = m[0]; tan[n - 1] = m[n - 2];
  for (let i = 1; i < n - 1; i++) tan[i] = m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2;
  for (let i = 0; i < n - 1; i++) { if (m[i] === 0) { tan[i] = tan[i + 1] = 0; continue; } const a = tan[i] / m[i], b = tan[i + 1] / m[i], s = a * a + b * b; if (s > 9) { const t = 3 / Math.sqrt(s); tan[i] = t * a * m[i]; tan[i + 1] = t * b * m[i]; } }
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < n - 1; i++) d += `C${pts[i][0] + dx[i] / 3},${pts[i][1] + tan[i] * dx[i] / 3} ${pts[i + 1][0] - dx[i] / 3},${pts[i + 1][1] - tan[i + 1] * dx[i] / 3} ${pts[i + 1][0]},${pts[i + 1][1]}`;
  return d;
}
const niceMax = v => { if (v <= 4) return 4; const p = 10 ** Math.floor(Math.log10(v)), f = v / p; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p; };

/* Requests (accent) and flagged (red) over time, with hover crosshair and tooltip. Redraws at its real width. */
function areaChart(points, { height = 220 } = {}) {
  const data = bucketize(points), box = h('div', { class: 'chart', style: `height:${height}px` });
  if (!data.length) { box.append(h('div', { class: 'chart-empty' }, h('b', {}, 'No traffic in this window'), h('span', {}, 'Requests appear here as soon as they pass through the gateway.'))); return box; }
  const pad = { l: 36, r: 8, t: 10, b: 22 };
  function draw() {
    const W = Math.max(box.clientWidth, 120), H = height, iw = W - pad.l - pad.r, ih = H - pad.t - pad.b, max = niceMax(Math.max(...data.map(d => d.requests)));
    const X = i => pad.l + (data.length === 1 ? iw / 2 : i * iw / (data.length - 1)), Y = v => pad.t + ih - (v / max) * ih;
    const req = data.map((d, i) => [X(i), Y(d.requests)]), flg = data.map((d, i) => [X(i), Y(d.flagged)]);
    const line = smoothPath(req), area = d => `${d}L${X(data.length - 1)},${pad.t + ih}L${X(0)},${pad.t + ih}Z`, fline = smoothPath(flg);
    const s = svg('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Requests and flagged requests over time' });
    s.append(svg('defs', {}, ...[['gA', 'var(--accent)', .3], ['gB', 'var(--bad)', .34]].map(([id, c, o]) => svg('linearGradient', { id, x1: 0, y1: 0, x2: 0, y2: 1 }, svg('stop', { offset: '0%', style: `stop-color:${c};stop-opacity:${o}` }), svg('stop', { offset: '100%', style: `stop-color:${c};stop-opacity:0` })))));
    for (const f of [0, .5, 1]) {
      const y = Y(max * f); s.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: y, y2: y, class: 'grid-line' }), svg('text', { x: pad.l - 8, y: y + 4, class: 'axis', 'text-anchor': 'end' }, String(Math.round(max * f))));
    }
    const ticks = Math.min(5, data.length), long = data[data.length - 1].t - data[0].t > 86400;
    for (let k = 0; k < ticks; k++) { const i = ticks === 1 ? 0 : Math.round(k * (data.length - 1) / (ticks - 1)); s.append(svg('text', { x: X(i), y: H - 4, class: 'axis', 'text-anchor': k === 0 ? 'start' : k === ticks - 1 ? 'end' : 'middle' }, long ? dayClock(data[i].t).split(',')[0] : clock(data[i].t))); }
    if (data.length > 1) s.append(svg('path', { d: area(line), style: 'fill:url(#gA)' }), svg('path', { d: line, class: 'ln', style: 'stroke:var(--accent)' }), svg('path', { d: area(fline), style: 'fill:url(#gB)' }), svg('path', { d: fline, class: 'ln', style: 'stroke:var(--bad)' }));
    else s.append(svg('circle', { cx: X(0), cy: Y(data[0].requests), r: 4, style: 'fill:var(--accent)' }));
    const cross = svg('line', { y1: pad.t, y2: pad.t + ih, class: 'cross', style: 'opacity:0' }), d1 = svg('circle', { r: 4.5, class: 'dot-a', style: 'opacity:0' }), d2 = svg('circle', { r: 4.5, class: 'dot-b', style: 'opacity:0' });
    s.append(cross, d1, d2);
    const tip = h('div', { class: 'chart-tip material', hidden: true });
    const at = e => {
      const r = s.getBoundingClientRect(), x = Math.min(Math.max(e.clientX - r.left, pad.l), W - pad.r), i = Math.round((x - pad.l) / iw * (data.length - 1) || 0), d = data[Math.max(0, Math.min(data.length - 1, i))], cx = X(data.indexOf(d));
      cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.style.opacity = 1;
      d1.setAttribute('cx', cx); d1.setAttribute('cy', Y(d.requests)); d1.style.opacity = 1; d2.setAttribute('cx', cx); d2.setAttribute('cy', Y(d.flagged)); d2.style.opacity = d.flagged ? 1 : 0;
      tip.hidden = false; tip.replaceChildren(h('b', {}, long ? dayClock(d.t) : clock(d.t)), h('span', {}, h('i', { class: 'sw', style: 'background:var(--accent)' }), `${d.requests} requests`), h('span', {}, h('i', { class: 'sw', style: 'background:var(--bad)' }), `${d.flagged} flagged${d.requests ? ` · ${(d.flagged / d.requests * 100).toFixed(0)}%` : ''}`));
      const tw = tip.offsetWidth, left = cx + 14 + tw > W ? cx - 14 - tw : cx + 14; tip.style.transform = `translate(${Math.max(0, left)}px, ${pad.t}px)`;
    };
    const off = () => { cross.style.opacity = d1.style.opacity = d2.style.opacity = 0; tip.hidden = true; };
    s.addEventListener('pointermove', at); s.addEventListener('pointerleave', off); s.addEventListener('pointerdown', at);
    box.replaceChildren(s, tip, h('div', { class: 'legend' }, h('span', {}, h('i', { class: 'sw', style: 'background:var(--accent)' }), 'Requests'), h('span', {}, h('i', { class: 'sw', style: 'background:var(--bad)' }), 'Flagged')));
  }
  new ResizeObserver(() => { if (box.isConnected) draw(); }).observe(box); requestAnimationFrame(draw);
  return box;
}
function sparkline(values, color = 'var(--accent)') {
  const W = 96, H = 28, max = Math.max(1, ...values), pts = values.map((v, i) => [values.length < 2 ? W / 2 : i * (W - 2) / (values.length - 1) + 1, H - 3 - (v / max) * (H - 6)]);
  if (values.length < 2) return h('span', { class: 'spark' });
  const d = smoothPath(pts), id = 'sp' + Math.random().toString(36).slice(2, 7);
  return h('span', { class: 'spark' }, svg('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, 'aria-hidden': 'true' },
    svg('defs', {}, svg('linearGradient', { id, x1: 0, y1: 0, x2: 0, y2: 1 }, svg('stop', { offset: '0%', style: `stop-color:${color};stop-opacity:.3` }), svg('stop', { offset: '100%', style: `stop-color:${color};stop-opacity:0` }))),
    svg('path', { d: `${d}L${W - 1},${H}L1,${H}Z`, style: `fill:url(#${id})` }), svg('path', { d, class: 'ln', style: `stroke:${color}` })));
}
/* Fused risk against the alert threshold: faint zones, a filled bar that springs in, and the threshold tick. */
function riskGauge(risk, thr) {
  const flag = risk >= thr, fill = h('i', { class: 'fill' }), knob = h('u', { class: 'knob' });
  const g = h('div', { class: 'gauge' + (flag ? ' flag' : '') },
    h('div', { class: 'gauge-head' }, h('span', { class: 'gauge-num' }, risk.toFixed(2)), h('span', { class: 'muted' }, flag ? 'at or above the threshold' : 'below the threshold')),
    h('div', { class: 'gauge-track', role: 'img', 'aria-label': `Risk ${risk.toFixed(2)} against threshold ${thr}` },
      h('b', { class: 'zone', style: `left:0;width:30%` }), h('b', { class: 'zone warn', style: `left:30%;width:${Math.max(0, thr * 100 - 30)}%` }), h('b', { class: 'zone bad', style: `left:${thr * 100}%;right:0` }),
      fill, knob, h('s', { class: 'tick', style: `left:${thr * 100}%` }, h('em', {}, `Threshold ${thr}`))));
  spring({ from: 0, to: risk, response: .7, damping: .86, eps: .0005, onUpdate: x => { const p = Math.max(0, x) * 100; fill.style.width = p + '%'; knob.style.left = p + '%'; } });
  return g;
}
/* One row per detector, in its own colour; the tick marks the 0.5 level at which a detector alerts alone. */
const DET_KEY = { rules: 'rules', 'payload ML': 'ml', payload_ml: 'ml', ml: 'ml', behavior: 'behavior', schema: 'schema', coraza: 'waf' };
const detKey = n => DET_KEY[n] || 'rules';
function detectorBars(entries) {
  return h('div', { class: 'det-list' }, entries.map(([name, v]) => {
    const fill = h('i', { style: 'width:0' });
    spring({ from: 0, to: v, response: .55, eps: .0005, onUpdate: x => { fill.style.width = Math.max(0, x) * 100 + '%'; } });
    return h('div', { class: 'det d-' + detKey(name) }, h('div', { class: 'row' }, h('span', { class: 'dot-d' }), h('b', {}, name), h('span', { class: 'grow' }), h('span', { class: 'num' }, v.toFixed(2))), h('div', { class: 'bar' }, fill, h('s', { class: 'half' })));
  }));
}

/* ---- segmented control with a springy thumb ------------------------------------------------------- */
function segmented(options, value, onchange, label) {
  const thumb = h('i', { class: 'thumb' }), btns = options.map(([v, l]) => h('button', { type: 'button', 'aria-pressed': String(v === value), 'data-v': v, onclick: () => select(v, true) }, l));
  const root = h('div', { class: 'seg', role: 'group', 'aria-label': label }, thumb, btns);
  let sx, sw;
  const place = (animate) => {
    const b = btns.find(x => x.dataset.v === String(value)); if (!b || !b.offsetWidth) return;
    if (!animate || sx == null) { thumb.style.transform = `translateX(${b.offsetLeft}px)`; thumb.style.width = b.offsetWidth + 'px'; sx = { value: b.offsetLeft }; return; }
    sx.sp && sx.sp.stop(); const w0 = thumb.offsetWidth, x0 = sx.value;
    sx.sp = spring({ from: 0, to: 1, response: .38, damping: .85, eps: .001, onUpdate: t => { sx.value = x0 + (b.offsetLeft - x0) * t; thumb.style.transform = `translateX(${sx.value}px)`; thumb.style.width = w0 + (b.offsetWidth - w0) * t + 'px'; } });
  };
  function select(v, user) { value = v; btns.forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === String(v)))); place(true); if (user) onchange(v); }
  root.set = v => select(v, false);
  new ResizeObserver(() => place(false)).observe(root); requestAnimationFrame(() => place(false));
  return root;
}

/* ---- sheet: the detail drawer (side panel on desktop, bottom sheet on phones) -------------------------
   Opens from the right/bottom and leaves the same way. Drag the bar: it follows the pointer 1:1,
   rubber-bands past its resting place, and on release a flick is projected forward to decide whether
   it closes. Grab it again while it moves and it continues from where it is, with the velocity it had. */
const Sheet = (() => {
  const el = $('drawer'), scrim = $('drawerScrim'), bar = el.querySelector('.drawer-bar');
  let open = false, pos = 0, size = 0, axis = 'x', sp = null, from = null, drag = null;
  const phone = () => matchMedia('(max-width:700px)').matches;
  const measure = () => { axis = phone() ? 'y' : 'x'; size = axis === 'x' ? el.offsetWidth : el.offsetHeight; };
  const apply = p => { pos = p; el.style.transform = axis === 'x' ? `translate3d(${p}px,0,0)` : `translate3d(0,${p}px,0)`; scrim.style.opacity = String(Math.max(0, Math.min(1, 1 - p / (size || 1)))); };
  const finish = () => { if (open) return; el.hidden = true; el.inert = true; el.setAttribute('aria-hidden', 'true'); scrim.hidden = true; el.style.opacity = ''; if (from && document.contains(from)) from.focus(); from = null; };
  function show(title, body) {
    $('drawerTitle').textContent = title; $('drawerBody').replaceChildren(body); $('drawerBody').scrollTop = 0; el.scrollTop = 0;
    if (open) return;
    from = document.activeElement; open = true; sp && sp.stop();
    el.hidden = false; scrim.hidden = false; el.inert = false; el.setAttribute('aria-hidden', 'false'); measure();
    if (prefersReduced.matches) { el.style.transform = 'none'; scrim.style.opacity = '1'; el.style.opacity = '0'; requestAnimationFrame(() => { el.style.transition = 'opacity .15s'; el.style.opacity = '1'; }); }
    else { apply(size); sp = spring({ from: size, to: 0, response: .4, damping: .9, eps: .4, onUpdate: apply }); }
    $('drawerClose').focus({ preventScroll: true });
  }
  function close(velocity = 0) {
    if (!open) return; open = false; sp && sp.stop();
    if (prefersReduced.matches) { el.style.transition = 'opacity .15s'; el.style.opacity = '0'; scrim.style.opacity = '0'; setTimeout(finish, 160); return; }
    sp = spring({ from: pos, to: size, velocity, response: .36, damping: 1, eps: .5, onUpdate: apply, onDone: finish });
  }
  const along = e => axis === 'x' ? e.clientX : e.clientY;
  bar.addEventListener('pointerdown', e => {
    if (e.target.closest('button') || !open) return;
    bar.setPointerCapture(e.pointerId); sp && sp.stop(); measure();
    drag = { id: e.pointerId, start: along(e), p0: pos, hist: [[performance.now(), pos]] }; el.classList.add('dragging');
  });
  bar.addEventListener('pointermove', e => {
    if (!drag || e.pointerId !== drag.id) return;
    const raw = drag.p0 + along(e) - drag.start, p = raw < 0 ? -rubberband(-raw, size) : raw;
    apply(p); drag.hist.push([performance.now(), p]); if (drag.hist.length > 6) drag.hist.shift();
  });
  const release = e => {
    if (!drag || e.pointerId !== drag.id) return;
    const [t0, p0] = drag.hist[0], [t1, p1] = drag.hist[drag.hist.length - 1], v = t1 > t0 ? (p1 - p0) / ((t1 - t0) / 1000) : 0;
    drag = null; el.classList.remove('dragging');
    if (pos + project(v) > size / 2) close(v);                              // decide by where the flick would land
    else sp = spring({ from: pos, to: 0, velocity: v, response: .38, damping: Math.abs(v) > 250 ? .8 : 1, eps: .4, onUpdate: apply });
  };
  bar.addEventListener('pointerup', release); bar.addEventListener('pointercancel', release);
  $('drawerClose').onclick = () => close(); scrim.onclick = () => close();
  addEventListener('keydown', e => { if (e.key === 'Escape' && open && !$('dlg').open && !document.querySelector('.palette:not([hidden])')) close(); });
  addEventListener('focusin', e => { if (open && !$('dlg').open && !el.contains(e.target) && !e.target.closest('.palette,#toast')) $('drawerClose').focus(); });
  return { show, close, get isOpen() { return open; } };
})();
const openDrawer = (t, b) => Sheet.show(t, b), closeDrawer = () => Sheet.close();

/* ---- toasts (with Undo for anything reversible) --------------------------------------------------- */
let toastTimer, toastSp;
function toast(msg, { undo, ms = 4500 } = {}) {
  const t = $('toast'); clearTimeout(toastTimer);
  t.replaceChildren(h('span', {}, msg), undo ? h('button', { class: 'toast-btn', onclick: () => { hide(); undo(); } }, 'Undo') : null);
  t.hidden = false; toastSp && toastSp.stop();
  toastSp = spring({ from: 1, to: 0, response: .4, damping: .85, eps: .002, onUpdate: x => { t.style.transform = `translate(-50%,${x * 28}px) scale(${1 - x * .04})`; t.style.opacity = String(1 - Math.min(1, x)); } });
  const hide = () => { toastSp.stop(); toastSp = spring({ from: toastSp.value, to: 1, response: .3, eps: .004, onUpdate: x => { t.style.transform = `translate(-50%,${x * 28}px) scale(${1 - x * .04})`; t.style.opacity = String(1 - Math.min(1, x)); }, onDone: () => { t.hidden = true; } }); };
  t._hide = hide; toastTimer = setTimeout(hide, ms);
  t.onpointerenter = () => clearTimeout(toastTimer); t.onpointerleave = () => { toastTimer = setTimeout(hide, 1800); };
}

/* ---- theme: follow the system, or force light / dark ---------------------------------------------- */
const Theme = {
  get: () => { try { return localStorage.theme || 'auto'; } catch { return 'auto'; } },
  apply(v = Theme.get()) { if (v === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.dataset.theme = v; },
  cycle() { const next = { auto: 'light', light: 'dark', dark: 'auto' }[Theme.get()]; try { localStorage.theme = next; } catch {} Theme.apply(next); return next; },
};
Theme.apply();

/* ---- command palette (Cmd/Ctrl+K) and shortcuts ---------------------------------------------------- */
const ui = { commands: () => [] };      // app.js fills this in
const Palette = (() => {
  let root, input, list, items = [], sel = 0, from, timer, sp, live = 0;
  function build() {
    input = h('input', { placeholder: 'Search pages, actions, clients, paths…', 'aria-label': 'Command', autocomplete: 'off', spellcheck: 'false', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'palList' });
    list = h('div', { class: 'palette-list', id: 'palList', role: 'listbox' });
    root = h('div', { class: 'palette', hidden: true, role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Command palette' },
      h('div', { class: 'palette-scrim', onclick: close }),
      h('div', { class: 'palette-panel material' }, h('div', { class: 'palette-input' }, icon('search', 18), input, h('kbd', {}, 'esc')), list,
        h('div', { class: 'palette-foot' }, h('span', {}, h('kbd', {}, '↑'), h('kbd', {}, '↓'), ' move'), h('span', {}, h('kbd', {}, '↵'), ' open'), h('span', {}, h('kbd', {}, '?'), ' shortcuts'))));
    document.body.append(root);
    input.addEventListener('input', () => { render(); lookup(); });
    input.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); move(1); } else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
      else if (e.key === 'Enter') { e.preventDefault(); run(items[sel]); } else if (e.key === 'Escape') { e.preventDefault(); close(); }
      else if (e.key === 'Tab') e.preventDefault();
    });
  }
  const score = (it, q) => { const s = (it.label + ' ' + (it.hint || '') + ' ' + (it.group || '')).toLowerCase(); return q.split(/\s+/).every(w => s.includes(w)) ? (it.label.toLowerCase().startsWith(q) ? 2 : 1) : 0; };
  let extra = [];
  function render() {
    const q = input.value.trim().toLowerCase();
    items = [...ui.commands().filter(c => !q || score(c, q)).sort((a, b) => q ? score(b, q) - score(a, q) : 0), ...extra].slice(0, 14);
    sel = Math.min(sel, Math.max(0, items.length - 1));
    list.replaceChildren(...(items.length ? items.map((it, i) => h('div', { class: 'pal-item' + (i === sel ? ' sel' : ''), role: 'option', 'aria-selected': String(i === sel), onpointermove: () => { if (sel !== i) { sel = i; mark(); } }, onclick: () => run(it) },
      h('span', { class: 'pal-ico' }, icon(it.icon || 'events', 16)), h('span', { class: 'pal-label' }, it.label), it.hint ? h('span', { class: 'pal-hint' }, it.hint) : null, h('span', { class: 'pal-group' }, it.group || ''))) : [h('div', { class: 'pal-empty' }, 'No matches. Try a full client IP, or part of a path.')]));
  }
  const mark = () => [...list.children].forEach((c, i) => { c.classList.toggle('sel', i === sel); c.setAttribute('aria-selected', String(i === sel)); if (i === sel) c.scrollIntoView({ block: 'nearest' }); });
  const move = d => { sel = (sel + d + items.length) % Math.max(1, items.length); mark(); };
  function lookup() {                    // clients and request paths come from the live event log
    clearTimeout(timer); const q = input.value.trim(), mine = ++live; extra = [];
    if (q.length < 2) return;
    timer = setTimeout(async () => {
      try {
        const isIp = /^[\d.:a-f]+$/i.test(q) && /\d/.test(q), evs = (await gw('/events?limit=6&' + (isIp ? 'ip=' : 'path=') + encodeURIComponent(q))).events;
        if (mine !== live || root.hidden) return;
        extra = evs.map(e => ({ group: 'Event', icon: 'events', label: `${e.method} ${e.path}`, hint: `${e.client_ip} · risk ${e.risk.toFixed(2)}`, run: () => openEvent(e.id) })); render();
      } catch { /* the palette still works for pages and actions */ }
    }, 160);
  }
  function run(it) { if (!it) return; close(true); setTimeout(() => it.run(), 30); }
  function show() {
    if (!root) build(); if (!root.hidden) return;
    from = document.activeElement; input.value = ''; extra = []; sel = 0; render(); root.hidden = false; input.focus();
    const panel = root.querySelector('.palette-panel'), scrim = root.querySelector('.palette-scrim');
    sp && sp.stop(); sp = spring({ from: 0, to: 1, response: .32, damping: .88, eps: .002, onUpdate: x => { panel.style.opacity = String(Math.min(1, x)); panel.style.transform = `translateY(${(1 - x) * -12}px) scale(${.96 + .04 * x})`; scrim.style.opacity = String(Math.min(1, x)); } });
  }
  function close(keepFocus) { if (!root || root.hidden) return; root.hidden = true; live++; if (!keepFocus && from && document.contains(from)) from.focus(); }
  addEventListener('keydown', e => { if (e.key === 'Escape' && root && !root.hidden) { e.preventDefault(); close(); } });   // works wherever the focus is
  return { show, close, get open() { return !!root && !root.hidden; } };
})();

function shortcutSheet() {
  const row = (keys, text) => h('div', { class: 'row sc' }, h('span', {}, text), h('span', { class: 'keys' }, keys.map(k => h('kbd', {}, k))));
  openDrawer('Keyboard shortcuts', h('div', { class: 'stack' },
    h('div', {}, h('h3', {}, 'Anywhere'), row(['⌘', 'K'], 'Command palette (also Ctrl K, or /)'), row(['?'], 'This list'), row(['Esc'], 'Close the panel or palette')),
    h('div', {}, h('h3', {}, 'Go to (press G, then)'), ui.commands().filter(c => c.key).map(c => row(['G', c.key.toUpperCase()], c.label))),
    h('p', { class: 'muted' }, 'Shortcuts are off while you type in a field.')));
}
let goPending = 0;
addEventListener('keydown', e => {
  if ($('app').hidden) return;
  const typing = e.target.closest && e.target.closest('input,textarea,select,[contenteditable]');
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); Palette.open ? Palette.close() : Palette.show(); return; }
  if (typing || e.metaKey || e.ctrlKey || e.altKey || Palette.open || $('dlg').open) return;
  if (e.key === '/') { e.preventDefault(); Palette.show(); }
  else if (e.key === '?') { e.preventDefault(); shortcutSheet(); }
  else if (e.key.toLowerCase() === 'g') goPending = Date.now();
  else if (goPending && Date.now() - goPending < 1200) { const c = ui.commands().find(x => x.key === e.key.toLowerCase()); goPending = 0; if (c) { e.preventDefault(); c.run(); } }
});
