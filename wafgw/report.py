"""Security reports for a time window: JSON for machines, one self-contained HTML page for people.

The HTML has no external resources and print CSS, so "Print > Save as PDF" in a browser gives a clean PDF.
"""
import asyncio
import html
import json
import time
from collections import Counter
from pathlib import Path

import httpx

from wafgw import incidents as inc

CAP = 20000                    # flagged events analysed per report; the report says so when it hits the cap
CONTEXT_RUNS = 150             # incidents that also look at the client's non-flagged requests (for impact analysis)
DET = inc.LIVE


def _rows(store, sql: str, *args) -> list[dict]:
    return store._rows(sql, args)


def build_report(store, since: float, until: float | None = None, info: dict | None = None, gap_s: float = inc.GAP_S) -> dict:
    until = until or time.time()
    info = info or {}
    n = lambda v: v or 0
    t = _rows(store, "SELECT COUNT(*) n, SUM(action != 'allowed') flagged, SUM(action = 'blocked') blocked, SUM(action = 'would_block') would,"
                     " AVG(risk) avg_risk, AVG(latency_ms) lat FROM events WHERE ts >= ? AND ts < ?", since, until)[0]
    bucket = max(60, int((until - since) / 48 // 60 * 60) or 60)
    timeline = _rows(store, "SELECT CAST(ts / ? AS INT) * ? t, COUNT(*) requests, SUM(action != 'allowed') flagged FROM events "
                            "WHERE ts >= ? AND ts < ? GROUP BY 1 ORDER BY 1", bucket, bucket, since, until)
    top_paths = _rows(store, "SELECT path, COUNT(*) requests, SUM(action != 'allowed') flagged FROM events WHERE ts >= ? AND ts < ? "
                             "GROUP BY path ORDER BY 3 DESC, 2 DESC LIMIT 8", since, until)
    top_clients = _rows(store, "SELECT client_ip ip, COUNT(*) requests, SUM(action != 'allowed') flagged, MAX(risk) max_risk FROM events "
                               "WHERE ts >= ? AND ts < ? GROUP BY client_ip ORDER BY 3 DESC, 2 DESC LIMIT 8", since, until)
    status = {str(r["c"]): r["n"] for r in _rows(store, "SELECT COALESCE(upstream_status, 0) / 100 c, COUNT(*) n FROM events "
                                                        "WHERE ts >= ? AND ts < ? GROUP BY 1", since, until)}

    flagged = store.flagged(since, until, CAP)
    seen = [0]

    def ctx(ip, a, b):
        seen[0] += 1
        return store.events(ip=ip, since=a - 1, until=b, limit=1000) if seen[0] <= CONTEXT_RUNS else None
    incidents = inc.build_all(flagged, gap_s, ctx, limit=500)
    by_sev = Counter(i["severity"] for i in incidents)

    kinds: dict[str, dict] = {}
    for i in incidents:
        for c in i["classes"]:
            k = kinds.setdefault(c["key"], {"key": c["key"], "name": c["name"], "events": 0, "incidents": 0, "refs": c["refs"]})
            k["events"] += c["events"]
            k["incidents"] += 1
    attack_types = sorted(kinds.values(), key=lambda k: -k["events"])

    fired = Counter()
    pair = Counter()
    solo = Counter()
    for e in flagged:
        live = sorted({r["detector"] for r in e["reasons"] if r["strength"] >= .3 and r["detector"] in DET})
        fired.update(live)
        if len(live) == 1:
            solo[live[0]] += 1
        for a in live:
            for b in live:
                pair[(a, b)] += 1
    names = [d for d in DET if fired[d]]
    detectors = {"fired": dict(fired), "only_this": dict(solo), "labels": names,
                 "matrix": [[pair[(a, b)] for b in names] for a in names], "events_analysed": len(flagged), "capped": len(flagged) >= CAP}

    fb = [f for f in store.feedback() if since <= f["ts"] < until]
    benign = [e for e in (store.event(f["event_id"]) for f in fb if f["verdict"] == "benign") if e]
    fp = {"marked_benign": sum(f["verdict"] == "benign" for f in fb), "marked_attack": sum(f["verdict"] == "attack" for f in fb),
          "events": [{k: e[k] for k in ("id", "ts", "client_ip", "method", "path", "risk", "detectors")} for e in benign[:20]],
          "by_detector": dict(Counter(max(e["detectors"], key=e["detectors"].get) for e in benign if e["detectors"])),
          "exemptions": len(store.exemptions())}

    flagged_share = n(t["flagged"]) / t["n"] if t["n"] else 0.0
    succeeded = [i for i in incidents if i["outcome"]["level"] == "possibly_succeeded"]
    recs = []
    if succeeded and info.get("mode") == "monitor":
        recs.append({"priority": "high", "text": f"{len(succeeded)} incident(s) look like they succeeded while the gateway only monitors. Review them first, then switch to block mode."})
    elif succeeded:
        recs.append({"priority": "high", "text": f"{len(succeeded)} incident(s) may have succeeded despite the gateway. Check the application logs for those clients."})
    for i in incidents[:5]:
        if i["severity"] in ("critical", "high"):
            recs.append({"priority": i["severity"], "text": f"{i['summary']}: " + (i["recommendations"][0] if i["recommendations"] else "")})
    if fp["marked_benign"] >= 3:
        recs.append({"priority": "medium", "text": f"{fp['marked_benign']} events were marked benign. Review the Learning Inbox for scoped exemptions."})
    if flagged_share > .25 and info.get("mode") == "monitor":
        recs.append({"priority": "medium", "text": f"{flagged_share:.0%} of traffic was flagged. If this is production traffic, check for false positives before blocking."})
    for m in ("payload", "behavior", "schema"):
        if info.get("models") and not info["models"].get(m):
            recs.append({"priority": "low", "text": f"The {m} detector is not loaded, so its coverage is missing from this report."})
    seen_fix = set()
    for k in attack_types[:4]:
        for fix in inc.CATALOG[k["key"]]["fix"][:1]:
            if fix not in seen_fix:
                seen_fix.add(fix)
                recs.append({"priority": "info", "text": f"{k['name']}: {fix}"})

    top_kind = attack_types[0]["name"].lower() if attack_types else "no attacks"
    headline = (f"{t['n']:,} requests, {n(t['flagged']):,} flagged ({flagged_share:.1%}). {len(incidents)} incident(s)"
                + (f", {by_sev['critical']} critical, {by_sev['high']} high" if incidents else "")
                + f". Most common technique: {top_kind}.")
    return {"generated_at": time.time(), "window": {"since": since, "until": until, "hours": round((until - since) / 3600, 2)},
            "mode": info.get("mode"), "threshold": info.get("threshold"),
            "summary": {"requests": t["n"], "flagged": n(t["flagged"]), "blocked": n(t["blocked"]), "would_block": n(t["would"]),
                        "flagged_share": round(flagged_share, 4), "avg_risk": round(n(t["avg_risk"]), 4), "avg_latency_ms": round(n(t["lat"]), 2),
                        "incidents": len(incidents), "by_severity": {s: by_sev[s] for s in inc.SEVERITIES}, "succeeded": len(succeeded), "headline": headline},
            "traffic": {"bucket_s": bucket, "timeline": timeline, "top_paths": top_paths, "top_clients": top_clients, "status": status},
            "attack_types": attack_types, "incidents": incidents[:10], "false_positives": fp, "detectors": detectors, "recommendations": recs}


# --- HTML ----------------------------------------------------------------------------------------------------
CSS = """
:root{--ink:#1d1d1f;--mute:#6e6e73;--line:#d2d2d7;--bg:#fff;--soft:#f5f5f7;--accent:#0a64d6;--crit:#b00020;--high:#d4540a;--med:#a8760a;--low:#36735b}
*{box-sizing:border-box}body{margin:0;background:var(--soft);color:var(--ink);font:15px/1.5 -apple-system,'SF Pro Text','Helvetica Neue',Inter,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:40px 24px 64px;background:var(--bg)}
h1{font-size:30px;letter-spacing:-.02em;line-height:1.1;margin:0 0 4px}h2{font-size:20px;letter-spacing:-.01em;margin:36px 0 10px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:15px;margin:16px 0 6px}p{margin:6px 0}.mute{color:var(--mute)}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}
.kpi{background:var(--soft);border-radius:12px;padding:12px 14px}.kpi b{display:block;font-size:24px;letter-spacing:-.02em;font-variant-numeric:tabular-nums}.kpi span{font-size:12px;color:var(--mute)}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:500}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}code,.mono{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 9px;font-size:12px;margin:0 4px 4px 0;white-space:nowrap}
.sev-critical{background:var(--crit);color:#fff;border-color:var(--crit)}.sev-high{background:var(--high);color:#fff;border-color:var(--high)}.sev-medium{background:var(--med);color:#fff;border-color:var(--med)}.sev-low{background:var(--low);color:#fff;border-color:var(--low)}
.inc{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:14px 0;break-inside:avoid}.inc h3{margin:0 0 6px;font-size:16px}
.rec li{margin:4px 0}.pri{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute);margin-right:6px}
.cell{text-align:center;font-variant-numeric:tabular-nums}svg{max-width:100%;height:auto}footer{margin-top:40px;font-size:12px;color:var(--mute)}
@media(max-width:640px){.kpis{grid-template-columns:repeat(2,1fr)}}
@media print{body{background:#fff}main{padding:0;max-width:none}h2{break-after:avoid}.inc,tr{break-inside:avoid}@page{margin:16mm}}
"""
E = html.escape
when = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _chart(timeline: list[dict]) -> str:
    if not timeline:
        return '<p class="mute">No traffic in this window.</p>'
    w, h, pad = 880, 110, 4
    peak = max(max(p["requests"] for p in timeline), 1)
    bw = (w - 2 * pad) / len(timeline)
    bars = "".join(f'<rect x="{pad + i * bw:.1f}" y="{h - pad - p["requests"] / peak * (h - 2 * pad):.1f}" width="{max(bw - 1, 1):.1f}" '
                   f'height="{p["requests"] / peak * (h - 2 * pad):.1f}" fill="#c7c7cc"/>'
                   f'<rect x="{pad + i * bw:.1f}" y="{h - pad - (p["flagged"] or 0) / peak * (h - 2 * pad):.1f}" width="{max(bw - 1, 1):.1f}" '
                   f'height="{(p["flagged"] or 0) / peak * (h - 2 * pad):.1f}" fill="#d4540a"/>' for i, p in enumerate(timeline))
    return (f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Requests (grey) and flagged requests (orange) over time">{bars}</svg>'
            f'<p class="mute">Grey: requests. Orange: flagged. Peak {peak:,} requests per bar.</p>')


def _table(head: list[str], rows: list[list], num: set = frozenset()) -> str:
    th = "".join(f'<th class="{"n" if i in num else ""}">{E(h)}</th>' for i, h in enumerate(head))
    tr = "".join("<tr>" + "".join(f'<td class="{"n" if i in num else ""}">{c}</td>' for i, c in enumerate(r)) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{tr or '<tr><td colspan=%d class=mute>Nothing to show</td></tr>' % len(head)}</tbody></table>"


def _chips(refs: dict) -> str:
    return "".join(f'<span class="chip">{E(v)}</span>' for vals in refs.values() for v in (vals if isinstance(vals, list) else [vals]))


def _incident(i: dict) -> str:
    steps = "".join(
        f'<tr><td class="mono">{E(time.strftime("%H:%M:%S", time.localtime(s["ts"])))}</td><td class="n">{s["count"]}×</td>'
        f'<td class="mono">{E(s["method"])} {E(s["path"])}</td><td>{E(", ".join(inc.CATALOG[c]["name"] for c in s["classes"]))}</td>'
        f'<td class="mono">{E(s["evidence"][:70])}</td></tr>' for s in i["timeline"][:12] if "more" not in s)
    return (f'<div class="inc"><h3><span class="chip sev-{i["severity"]}">{i["severity"]}</span>{E(i["summary"])}</h3>'
            f'<p class="mute">{when(i["first_ts"])} – {when(i["last_ts"])} · confidence {i["confidence"]} · peak risk {i["max_risk"]:.2f}</p>'
            + "".join(f"<p>{E(p)}</p>" for p in i["narrative"]) + f'<p>{_chips(i["refs"])}</p>'
            + f'<table><thead><tr><th>Time</th><th class="n">Count</th><th>Request</th><th>Technique</th><th>Evidence</th></tr></thead><tbody>{steps}</tbody></table></div>')


def render_html(r: dict) -> str:
    s, w, tr, d, fp = r["summary"], r["window"], r["traffic"], r["detectors"], r["false_positives"]
    kpi = lambda v, l: f'<div class="kpi"><b>{v}</b><span>{l}</span></div>'
    sev = " ".join(f'<span class="chip sev-{k}">{v} {k}</span>' for k, v in reversed(list(s["by_severity"].items())) if v)
    attack = _table(["Technique", "Flagged requests", "Incidents", "References"],
                    [[E(k["name"]), f'{k["events"]:,}', k["incidents"], _chips(k["refs"])] for k in r["attack_types"]], {1, 2})
    labels = d["labels"]
    matrix = ""
    if labels:
        peak = max(max(row) for row in d["matrix"]) or 1
        head = "<tr><th></th>" + "".join(f"<th class='cell'>{E(l)}</th>" for l in labels) + "<th class='n'>fired alone</th></tr>"
        body = "".join(f"<tr><th>{E(a)}</th>" + "".join(
            f'<td class="cell" style="background:rgba(10,100,214,{.08 + .5 * v / peak:.2f})">{v}</td>' for v in row)
            + f"<td class='n'>{d['only_this'].get(a, 0)}</td></tr>" for a, row in zip(labels, d["matrix"]))
        matrix = f"<table>{head}{body}</table>"
    fps = _table(["When", "Client", "Request", "Risk"], [[when(e["ts"]), f'<span class="mono">{E(e["client_ip"])}</span>', f'<span class="mono">{E(e["method"])} {E(e["path"])}</span>', f'{e["risk"]:.2f}'] for e in fp["events"]], {3})
    recs = "".join(f'<li><span class="pri">{E(x["priority"])}</span>{E(x["text"])}</li>' for x in r["recommendations"]) or '<li class="mute">Nothing needs attention.</li>'
    cap = '<p class="mute">Only the newest 20,000 flagged requests were analysed.</p>' if d["capped"] else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis security report {when(w["since"])}</title><style>{CSS}</style></head><body><main>
<p class="mute">Aegis WAF · security report</p><h1>{when(w["since"])} → {when(w["until"])}</h1>
<p class="mute">{w["hours"]} hours · gateway mode: {E(str(r["mode"] or "unknown"))} · threshold {r["threshold"] if r["threshold"] is not None else "n/a"} · generated {when(r["generated_at"])}</p>
<h2 style="border:0;margin-top:20px">Executive summary</h2><p>{E(s["headline"])}</p>
<div class="kpis">{kpi(f'{s["requests"]:,}', "requests")}{kpi(f'{s["flagged"]:,}', "flagged")}{kpi(f'{s["blocked"]:,}', "blocked")}{kpi(f'{s["would_block"]:,}', "would have blocked")}
{kpi(s["incidents"], "incidents")}{kpi(s["succeeded"], "possibly succeeded")}{kpi(f'{s["avg_latency_ms"]:.1f} ms', "avg time in gateway")}{kpi(f'{s["avg_risk"]:.2f}', "mean risk")}</div>
<p>{sev}</p>
<h2>Traffic</h2>{_chart(tr["timeline"])}
<h3>Most flagged paths</h3>{_table(["Path", "Requests", "Flagged"], [[f'<span class="mono">{E(p["path"])}</span>', f'{p["requests"]:,}', f'{p["flagged"] or 0:,}'] for p in tr["top_paths"]], {1, 2})}
<h3>Most flagged clients</h3>{_table(["Client", "Requests", "Flagged", "Peak risk"], [[f'<span class="mono">{E(c["ip"])}</span>', f'{c["requests"]:,}', f'{c["flagged"] or 0:,}', f'{c["max_risk"]:.2f}'] for c in tr["top_clients"]], {1, 2, 3})}
<h2>Attack types</h2>{attack}{cap}
<h2>Notable incidents</h2>{"".join(_incident(i) for i in r["incidents"]) or '<p class="mute">No incidents in this window.</p>'}
<h2>False-positive review</h2><p>{fp["marked_benign"]} event(s) marked benign, {fp["marked_attack"]} confirmed as attacks, {fp["exemptions"]} exemption(s) active.
{"Detectors behind the benign events: " + E(", ".join(f"{k} ×{v}" for k, v in fp["by_detector"].items())) + "." if fp["by_detector"] else ""}</p>{fps}
<h2>Detector performance</h2><p class="mute">Number of flagged requests where each pair of detectors both fired (diagonal: each detector alone in total). “Fired alone” counts requests that only that detector caught: the unique value it adds.</p>{matrix or '<p class="mute">No detector data.</p>'}
<h2>Recommendations</h2><ol class="rec">{recs}</ol>
<footer>Generated by Aegis. Write-ups are rule-based; classifications map to OWASP API Security Top 10, OWASP Top 10 (2021), CWE and MITRE ATT&amp;CK as a guide, not an audit.</footer>
</main></body></html>"""


# --- files, schedule, delivery --------------------------------------------------------------------------------
def write_files(report: dict, directory: str) -> str:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    stem = time.strftime("%Y-%m-%d_%H%M", time.localtime(report["window"]["until"]))
    (out / f"{stem}.json").write_text(json.dumps(report, default=str))
    path = out / f"{stem}.html"
    path.write_text(render_html(report))
    return str(path)


def list_files(directory: str) -> list[dict]:
    d = Path(directory)
    return [{"name": p.name, "bytes": p.stat().st_size, "ts": p.stat().st_mtime} for p in sorted(d.glob("*.html"), reverse=True)] if d.is_dir() else []


async def deliver(store, report: dict, path: str, client: httpx.AsyncClient | None = None) -> str:
    """Send a short summary to the webhook configured for alerts (Slack, Discord or generic JSON)."""
    cfg = store.get("alerts", {}) or {}
    if not cfg.get("url"):
        return "no webhook configured"
    s = report["summary"]
    text = (f"Aegis report: {s['requests']:,} requests, {s['flagged']:,} flagged, {s['incidents']} incident(s) "
            f"({s['by_severity']['critical']} critical, {s['by_severity']['high']} high). Saved: {path}")
    body = {"slack": {"text": text}, "discord": {"content": text}}.get(cfg.get("kind", "generic"), {"text": text, "summary": s})
    own = client is None
    client = client or httpx.AsyncClient(timeout=5)
    try:
        return f"HTTP {(await client.post(cfg['url'], json=body)).status_code}"
    except httpx.HTTPError as exc:
        return f"failed: {type(exc).__name__}"
    finally:
        own and await client.aclose()


async def schedule(cfg: dict, store, engine) -> None:
    """Background task: write a report every [reports] every_h hours (the first one a minute after start if none is recent)."""
    rep = cfg.get("reports", {})
    if not rep.get("enabled"):
        await asyncio.Event().wait()                    # nothing to do; keep the gather() alive without spinning
    every = 3600 * float(rep.get("every_h", 24))
    last = max([f["ts"] for f in list_files(rep["dir"])] or [0])
    while True:
        await asyncio.sleep(max(60.0, last + every - time.time()))
        until = time.time()
        info = {"mode": engine.mode, "threshold": engine.threshold,
                "models": {"payload": engine.payload is not None, "behavior": engine.behavior is not None, "schema": engine.schema is not None}}
        built = await asyncio.to_thread(build_report, store, until - 3600 * float(rep.get("window_h", 24)), until, info)
        path = await asyncio.to_thread(write_files, built, rep["dir"])
        if rep.get("webhook"):
            await deliver(store, built, path)
        last = time.time()
