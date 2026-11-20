"""Management console: a thin, authenticated front for the gateway admin API plus the "intelligence" the UI needs
(explain, learning inbox, simulator, threats, alerts). The admin token stays on the server, never in the browser.

Env: WAF_ADMIN_URL (default http://127.0.0.1:9000), WAF_ADMIN_TOKEN, CONSOLE_PASSWORD (optional login).
"""
import asyncio
import contextlib
import hashlib
import hmac
import os
import time
from collections import Counter, defaultdict, deque
from functools import cache
from pathlib import Path

import httpx
import joblib
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from scipy.sparse import csr_matrix, hstack

from detection.ml_payload import _stats, request_text
from detection.rules import RULES, extract_values, normalize, stateless_hits
from detection.run_novel import requests as novel_requests
from wafgw.policy import DETECTORS, fuse, param_names, replay

router = APIRouter(prefix="/api")
PASSTHROUGH = {"events", "stats", "mode", "lists", "exemptions", "feedback", "audit", "routes", "policy", "settings", "health", "schema", "reload"}
_gw: httpx.AsyncClient | None = None
ALERT_LOG: deque = deque(maxlen=50)
RULE_BY_ID = {r.id: r for r in RULES}


# --- gateway access -------------------------------------------------------------------------------
def set_gateway_client(client: httpx.AsyncClient | None) -> None:
    global _gw
    _gw = client


async def gw(method: str, path: str, **kw):
    global _gw
    if _gw is None:
        _gw = httpx.AsyncClient(base_url=os.environ.get("WAF_ADMIN_URL", "http://127.0.0.1:9000"), timeout=10)
    headers = {"authorization": f"Bearer {os.environ.get('WAF_ADMIN_TOKEN', '')}", "x-actor": "console",
               "content-type": "application/json"}
    try:
        r = await _gw.request(method, path, headers=headers, **kw)
    except httpx.HTTPError:
        raise HTTPException(502, "gateway admin API unreachable (is `python -m wafgw` running with WAF_ADMIN_TOKEN?)")
    if r.status_code == 401:                              # the gateway refused OUR token; not a console login problem
        raise HTTPException(502, "gateway rejected the admin token (WAF_ADMIN_TOKEN must be the same for the gateway and the console)")
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.json().get("error", "gateway error") if "json" in r.headers.get("content-type", "") else "gateway error")
    return r.json()


# --- optional login -------------------------------------------------------------------------------
def _cookie_value() -> str:
    return hmac.new(os.environ["CONSOLE_PASSWORD"].encode(), b"console-session-v1", hashlib.sha256).hexdigest()


def authorized(request: Request) -> bool:
    if not os.environ.get("CONSOLE_PASSWORD"):
        return True
    return hmac.compare_digest(request.cookies.get("console", ""), _cookie_value())


@router.get("/session")
async def session(request: Request):
    required = bool(os.environ.get("CONSOLE_PASSWORD"))
    ok = authorized(request)
    gateway = False
    if ok:
        with contextlib.suppress(HTTPException):
            gateway = (await gw("GET", "/api/health"))["status"] == "ok"
    return {"auth_required": required, "logged_in": ok, "gateway_ok": gateway}


@router.post("/login")
async def login(request: Request, response: Response):
    pw = os.environ.get("CONSOLE_PASSWORD")
    if pw and not hmac.compare_digest((await request.json()).get("password", "").encode(), pw.encode()):
        await asyncio.sleep(0.5)                       # slows down guessing
        raise HTTPException(401, "wrong password")
    if pw:
        response.set_cookie("console", _cookie_value(), httponly=True, samesite="strict", max_age=86400)
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("console")
    return {"ok": True}


# --- plain pass-through to the gateway --------------------------------------------------------------
@router.api_route("/gw/{path:path}", methods=["GET", "POST", "DELETE"])
async def passthrough(path: str, request: Request):
    if path.split("/")[0] not in PASSTHROUGH:
        raise HTTPException(404, "unknown gateway call")
    body = await request.body()
    return await gw(request.method, f"/api/{path}", params=dict(request.query_params), content=body or None)


# --- explain ----------------------------------------------------------------------------------------
@cache
def payload_model():
    path = Path(os.environ.get("WAFGW_MODELS", "models")) / "payload.joblib"
    return joblib.load(path) if path.exists() else None


def ml_terms(ev: dict, top: int = 6) -> list[dict]:
    """The character n-grams that pushed the payload model towards 'attack' (coefficient x tf-idf)."""
    m = payload_model()
    if m is None:
        return []
    text, values = request_text(ev["method"], ev["path"], ev["query"], ev["body_snippet"] or "")
    X = hstack([m.tfidf.transform([text]), csr_matrix(m.scale.transform([_stats(values)]))]).tocsr()
    names, n_text = m.tfidf.get_feature_names_out(), len(m.tfidf.get_feature_names_out())
    contrib = [(names[i], float(v * m.clf.coef_[0][i])) for i, v in zip(X.indices, X.data) if i < n_text]
    contrib = [c for c in sorted(contrib, key=lambda c: -c[1]) if c[1] > 0 and len(c[0].strip()) >= 2][:top]
    return [{"ngram": n, "weight": round(w, 2)} for n, w in contrib]


def explain_event(ev: dict, threshold: float) -> dict:
    values = extract_values(ev["query"], ev["body_snippet"] or "")
    terms = []
    for r in ev["reasons"]:
        if r["detector"] != "rules":
            continue
        for rid in filter(None, str(r["detail"]).split(",")):
            rule = RULE_BY_ID.get(rid)
            if not rule:
                continue
            texts = [ev["user_agent"]] if rule.target == "user_agent" else [normalize(v) for v in values]
            m = next((x for t in texts if (x := rule.regex.search(t))), None)
            terms.append({"source": "rules", "rule": rid, "name": rule.name, "text": m.group(0) if m else ""})
    ml = ml_terms(ev) if ev["detectors"].get("payload ML", 0) >= 0.2 else []
    terms += [{"source": "payload ML", "text": t["ngram"].strip(), "weight": t["weight"]} for t in ml]
    return {"event": ev, "threshold": threshold, "terms": terms,
            "decoded": {"query": " & ".join(values) if ev["query"] else "", "body": ev["body_snippet"] or ""},
            "exempt": [r for r in ev["reasons"] if str(r["detail"]).startswith("exempt")]}


@router.get("/explain/{event_id}")
async def explain(event_id: int):
    ev = await gw("GET", f"/api/events/{event_id}")
    mode = await gw("GET", "/api/mode")
    return explain_event(ev, mode["threshold"])


# --- corpus (known attacks + look-alikes) used as a safety net for any policy change ------------------
@cache
def corpus() -> list[dict]:
    df, out = novel_requests(), []
    m = payload_model()
    for i, r in enumerate(df.itertuples()):
        score = sum(s for _, s in stateless_hits(r.query, r.body))
        det = {"rules": min(score / 10, 1.0)}
        if m is not None:
            text, values = request_text(r.method, r.path, r.query, r.body)
            det["payload ML"] = float(m.score([text], [_stats(values)])[0])
        out.append({"id": -(i + 1), "path": r.path, "query": r.query, "body_snippet": r.body, "detectors": det,
                    "label": int(r.label), "action": "allowed", "kind": r.attack_type})
    return out


def corpus_replay(threshold: float, current_threshold: float, exemptions: list[dict]) -> dict:
    data = corpus()
    for e in data:
        e["action"] = "blocked" if fuse(e["detectors"]) >= current_threshold else "allowed"
    rep = replay(data, threshold, exemptions)
    lost = [e for e in data if e["id"] in rep["newly_allowed"] and e["label"]]
    by_id = {e["id"]: e for e in data}
    flagged = lambda e: e["id"] not in rep["newly_allowed"] and (e["action"] != "allowed" or e["id"] in rep["newly_flagged"])
    return {"attacks": sum(e["label"] for e in data), "benign": sum(not e["label"] for e in data),
            "attacks_caught_before": sum(e["label"] and e["action"] != "allowed" for e in data),
            "attacks_caught_after": sum(e["label"] and flagged(e) for e in data),
            "false_alarms_before": sum(not e["label"] and e["action"] != "allowed" for e in data),
            "false_alarms_after": sum(not e["label"] and flagged(e) for e in data),
            "attacks_lost": [{"path": e["path"], "text": e["query"] or e["body_snippet"]} for e in lost],
            "new_false_alarms": [by_id[i]["query"] or by_id[i]["body_snippet"] for i in rep["newly_flagged"] if not by_id[i]["label"]]}


async def recent_events(limit: int = 1000, since_s: int = 7 * 86400) -> list[dict]:
    return (await gw("GET", "/api/events", params={"limit": limit, "since": time.time() - since_s}))["events"]


async def simulate_policy(threshold: float | None, exemptions: list[dict]) -> dict:
    mode = await gw("GET", "/api/mode")
    current, threshold = mode["threshold"], threshold or mode["threshold"]
    events = await recent_events()
    fb = {f["event_id"]: f["verdict"] for f in (await gw("GET", "/api/feedback"))["feedback"]}
    rep = replay(events, threshold, exemptions)
    by_id = {e["id"]: e for e in events}
    lost_known = [i for i in rep["newly_allowed"] if fb.get(i) == "attack"]
    corp = corpus_replay(threshold, current, exemptions)
    sample = lambda ids: [{k: by_id[i][k] for k in ("id", "method", "path", "query", "risk", "client_ip")} for i in ids[:8]]
    reasons = []
    if lost_known:
        reasons.append(f"{len(lost_known)} event(s) you marked as attacks would be allowed")
    if corp["attacks_lost"]:
        reasons.append(f"{len(corp['attacks_lost'])} known attack payload(s) from the corpus would be allowed")
    return {"threshold": threshold, "current_threshold": current, "stored": {**rep, "newly_allowed": len(rep["newly_allowed"]),
            "newly_flagged": len(rep["newly_flagged"]), "allowed_sample": sample(rep["newly_allowed"]),
            "flagged_sample": sample(rep["newly_flagged"]), "known_attacks_lost": lost_known}, "corpus": corp,
            "safe": not reasons, "blocked_because": reasons}


@router.post("/simulate")
async def simulate(request: Request):
    d = await request.json()
    return await simulate_policy(d.get("threshold"), d.get("exemptions", []))


@router.post("/apply")
async def apply(request: Request):
    """Apply a candidate threshold / new exemptions, but only if the simulation says no known attack is lost."""
    d = await request.json()
    current = (await gw("GET", "/api/exemptions"))["exemptions"]
    sim = await simulate_policy(d.get("threshold"), [*current, *d.get("exemptions", [])])
    if not sim["safe"]:
        raise HTTPException(409, "; ".join(sim["blocked_because"]))
    for e in d.get("exemptions", []):
        await gw("POST", "/api/exemptions", json=e)
    if d.get("threshold"):
        await gw("POST", "/api/mode", json={"threshold": d["threshold"]})
    return {"applied": True, "simulation": sim}


# --- overview, inbox, threats -------------------------------------------------------------------------
def top_detector(ev: dict) -> str:
    live = {k: v for k, v in ev["detectors"].items() if k in DETECTORS}
    return max(live, key=live.get) if live else ""


def example_param(ev: dict) -> str:
    names = sorted(param_names(ev["query"], ev["body_snippet"] or ""))
    return names[0] if names else ""


@router.get("/overview")
async def overview(since: int = 3600):
    stats, evs = await gw("GET", "/api/stats", params={"since": since}), await recent_events(1000, since)
    reasons = Counter()
    for e in evs:
        if e["action"] != "allowed":
            for r in e["reasons"]:
                if r["strength"] > 0 and r["detector"] in DETECTORS:
                    reasons[r["detector"] if r["detector"] != "rules" else f"rules: {r['detail']}"[:48]] += 1
    return {"stats": stats, "top_reasons": reasons.most_common(8), "suspects": await suspects(evs)}


async def suspects(evs: list[dict]) -> list[dict]:
    """Flagged requests that look like false positives: one detector, low margin, many different callers."""
    thr = (await gw("GET", "/api/mode"))["threshold"]
    groups = defaultdict(list)
    for e in evs:
        live = [d for d, s in e["detectors"].items() if d in DETECTORS and s >= 0.3]
        if e["action"] != "allowed" and len(live) == 1 and e["risk"] < thr + 0.2:
            groups[(e["path"], live[0])].append(e)
    out = [{"path": p, "detector": d, "count": len(v), "ips": len({e["client_ip"] for e in v}),
            "avg_risk": round(sum(e["risk"] for e in v) / len(v), 2), "example": v[0]["id"]}
           for (p, d), v in groups.items() if len(v) >= 2]
    return sorted(out, key=lambda s: -s["count"])[:5]


@router.get("/inbox")
async def inbox():
    mode = await gw("GET", "/api/mode")
    evs = await recent_events()
    fb = {f["event_id"]: f["verdict"] for f in (await gw("GET", "/api/feedback"))["feedback"]}
    current = (await gw("GET", "/api/exemptions"))["exemptions"]
    groups = defaultdict(list)
    for e in evs:
        d = top_detector(e)
        if e["action"] != "allowed" and d:
            groups[(e["path"], d)].append(e)
    out = []
    for (path, det), v in groups.items():
        benign = sum(fb.get(e["id"]) == "benign" for e in v)
        attack = sum(fb.get(e["id"]) == "attack" for e in v)
        avg = sum(e["risk"] for e in v) / len(v)
        weak = len(v) >= 3 and len({e["client_ip"] for e in v}) >= 2 and avg < 0.75
        if not (benign or weak) or attack:
            continue
        params = Counter(example_param(e) for e in v)
        cand = {"prefix": path, "param": params.most_common(1)[0][0], "detector": det, "note": "from learning inbox"}
        if any(c["prefix"] == path and c["detector"] == det and c["param"] == cand["param"] for c in current):
            continue
        sim = await simulate_policy(None, [*current, cand])
        out.append({"suggestion": cand, "events": len(v), "ips": len({e["client_ip"] for e in v}), "avg_risk": round(avg, 2),
                    "marked_benign": benign, "reason": "you marked these benign" if benign else "repeated low-confidence flags from several clients",
                    "example": v[0]["id"], "would_allow": sim["stored"]["newly_allowed"], "safe": sim["safe"],
                    "blocked_because": sim["blocked_because"], "corpus": {k: sim["corpus"][k] for k in ("attacks_caught_before", "attacks_caught_after", "attacks")}})
    return {"items": sorted(out, key=lambda i: (-i["marked_benign"], -i["events"]))}


@router.get("/threats")
async def threats():
    evs = await recent_events(1000, 86400)
    by_ip = defaultdict(list)
    for e in evs:
        by_ip[e["client_ip"]].append(e)
    denied = {l["ip"] for l in (await gw("GET", "/api/lists"))["lists"] if l["kind"] == "deny"}
    rows = [{"ip": ip, "requests": len(v), "flagged": sum(e["action"] != "allowed" for e in v),
             "max_risk": max(e["risk"] for e in v), "last_ts": max(e["ts"] for e in v), "denied": ip in denied,
             "top": Counter(top_detector(e) for e in v if e["action"] != "allowed").most_common(2)} for ip, v in by_ip.items()]
    return {"rows": sorted(rows, key=lambda r: (-r["max_risk"], -r["flagged"]))[:200]}


# --- alerts -------------------------------------------------------------------------------------------
def alert_body(kind: str, ev: dict) -> dict:
    line = f"WAF {ev['action']}: {ev['client_ip']} {ev['method']} {ev['path']} risk {ev['risk']:.2f} ({top_detector(ev) or 'n/a'})"
    return {"slack": {"text": line}, "discord": {"content": line}}.get(kind, {"event": {k: ev[k] for k in (
        "id", "ts", "client_ip", "method", "path", "action", "risk", "detectors")}, "text": line})


async def send_alert(cfg: dict, ev: dict) -> str:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(cfg["url"], json=alert_body(cfg.get("kind", "generic"), ev))
        status = f"HTTP {r.status_code}"
    except (httpx.HTTPError, KeyError) as exc:
        status = f"failed: {type(exc).__name__}"
    ALERT_LOG.appendleft({"ts": time.time(), "ip": ev["client_ip"], "path": ev["path"], "risk": ev["risk"], "status": status})
    return status


@router.post("/alerts/test")
async def alerts_test():
    cfg = (await gw("GET", "/api/settings/alerts"))["value"]
    if not cfg.get("url", "").startswith(("http://", "https://")):
        raise HTTPException(400, "set a webhook URL first")
    sample = {"id": 0, "ts": time.time(), "client_ip": "203.0.113.7", "method": "GET", "path": "/products/search", "action": "blocked",
              "risk": 0.97, "detectors": {"rules": 1.0, "payload ML": 0.97}}
    return {"status": await send_alert(cfg, sample)}


@router.get("/alerts/log")
async def alerts_log():
    return {"log": list(ALERT_LOG)}


async def alert_worker(poll_s: float = 5.0) -> None:
    """Poll new events; send a webhook for high-risk ones, at most once per (client, detector) per dedup window."""
    last, seen = time.time(), {}
    while True:
        await asyncio.sleep(poll_s)
        try:
            cfg = (await gw("GET", "/api/settings/alerts"))["value"]
            if not cfg.get("enabled") or not cfg.get("url"):
                last = time.time()
                continue
            evs = (await gw("GET", "/api/events", params={"since": last, "limit": 200}))["events"]
            last = time.time()
            for e in reversed(evs):
                key = (e["client_ip"], top_detector(e))
                if e["action"] != "allowed" and e["risk"] >= cfg.get("min_risk", 0.8) and e["ts"] - seen.get(key, 0) > cfg.get("dedup_s", 300):
                    seen[key] = e["ts"]
                    await send_alert(cfg, e)
        except HTTPException:
            pass                                          # gateway down: try again next round
