"""Admin API (separate port, bearer token). This is the contract the dashboard talks to; see wafgw/README.md."""
import hmac
import ipaddress
import time
from collections import Counter, defaultdict

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from wafgw.admin_incidents import routes as incident_routes

START = time.time()
SETTING_KEYS = {"alerts"}


def build_admin(engine, store, token: str | None, cfg: dict | None = None) -> Starlette:
    if not token:
        raise RuntimeError("WAF_ADMIN_TOKEN is not set: refusing to start the admin API without authentication")

    def guarded(fn):
        async def wrapper(request: Request):
            given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            if not hmac.compare_digest(given.encode(), token.encode()):
                return JSONResponse({"error": "unauthorized"}, 401, {"www-authenticate": "Bearer"})
            try:
                resp = await fn(request)
                if request.method != "GET":
                    store.audit(request.headers.get("x-actor", "admin"), f"{request.method} {request.url.path}",
                                (await request.body()).decode("utf-8", "replace"))
                return resp
            except (ValueError, KeyError) as exc:
                return JSONResponse({"error": f"bad request: {exc}"}, 400)
        return wrapper

    async def health(request):
        return JSONResponse({"status": "ok", "uptime_s": round(time.time() - START),
                             "models": {"payload": engine.payload is not None, "behavior": engine.behavior is not None,
                                    "schema": engine.schema is not None}, "reload_errors": engine.reload_errors})

    async def stats(request):
        return JSONResponse({**store.stats(int(request.query_params.get("since", 3600))),
                             "mode": engine.mode, "threshold": engine.threshold})

    async def events(request):
        q = request.query_params
        return JSONResponse({"events": store.events(
            since=float(q.get("since", 0)), action=q.get("action"), ip=q.get("ip"), path=q.get("path"),
            min_risk=float(q.get("min_risk", 0)), before_id=int(q["before_id"]) if "before_id" in q else None,
            limit=int(q.get("limit", 100)))})

    async def mode(request):
        if request.method == "POST":
            data = await request.json()
            engine.set_mode(data.get("mode"), data.get("threshold"))
        return JSONResponse({"mode": engine.mode, "threshold": engine.threshold})

    async def lists(request):
        if request.method == "POST":
            data = await request.json()
            store.add_list(data["ip"], data["kind"], data.get("note", ""))
        elif request.method == "DELETE":
            if not store.remove_list(request.path_params["ip"].replace("_", "/")):
                return JSONResponse({"error": "not found"}, 404)
        return JSONResponse({"lists": store.lists()})

    async def one_event(request):
        ev = store.event(int(request.path_params["id"]))
        if ev is None:
            return JSONResponse({"error": "not found"}, 404)
        ev["feedback"] = next((f for f in store.feedback() if f["event_id"] == ev["id"]), None)
        return JSONResponse(ev)

    async def feedback(request):
        if request.method == "POST":
            d = await request.json()
            store.set_feedback(int(d["event_id"]), d["verdict"], d.get("note", ""))
        return JSONResponse({"feedback": store.feedback()})

    async def exemptions(request):
        if request.method == "POST":
            d = await request.json()
            store.add_exemption(d["prefix"], d["detector"], d.get("param", ""), d.get("note", ""))
        elif request.method == "DELETE":
            if not store.remove_exemption(int(request.path_params["id"])):
                return JSONResponse({"error": "not found"}, 404)
        return JSONResponse({"exemptions": store.exemptions()})

    async def routes(request):
        if request.method == "POST":
            engine.set_routes((await request.json())["routes"])
        return JSONResponse({"routes": engine.routes})

    async def audit(request):
        return JSONResponse({"audit": store.audit_log(int(request.query_params.get("limit", 200)))})

    async def setting(request):
        key = request.path_params["key"]
        if key not in SETTING_KEYS:
            return JSONResponse({"error": "unknown setting"}, 404)
        if request.method == "POST":
            store.put(key, await request.json())
        return JSONResponse({"value": store.get(key, {})})

    def policy_doc() -> dict:
        return {"version": 1, "mode": engine.mode, "threshold": engine.threshold, "routes": engine.routes,
                "lists": [{k: l[k] for k in ("ip", "kind", "note")} for l in store.lists()],
                "exemptions": [{k: e[k] for k in ("prefix", "param", "detector", "note")} for e in store.exemptions()],
                "alerts": store.get("alerts", {})}

    async def policy(request):
        if request.method == "POST":
            d = await request.json()
            if d.get("version") != 1:
                raise ValueError("unsupported policy version")
            # validate everything first, then apply: a bad file must not leave a half-applied policy
            for l in d.get("lists", []):
                ipaddress.ip_network(l["ip"], strict=False)
                if l["kind"] not in ("allow", "deny"):
                    raise ValueError("list kind must be allow or deny")
            engine.set_routes(d.get("routes", []))
            engine.set_mode(d.get("mode"), d.get("threshold"))
            for l in store.lists():
                store.remove_list(l["ip"])
            for l in d.get("lists", []):
                store.add_list(l["ip"], l["kind"], l.get("note", ""))
            for e in store.exemptions():
                store.remove_exemption(e["id"])
            for e in d.get("exemptions", []):
                store.add_exemption(e["prefix"], e["detector"], e.get("param", ""), e.get("note", ""))
            store.put("alerts", d.get("alerts", {}))
        return JSONResponse(policy_doc())

    async def reload(request):
        return JSONResponse(engine.reload())

    async def schema(request):
        """Learned/declared API schema plus how often each kind of schema finding fired in the last 24 h."""
        kinds = Counter()
        for e in store.events(since=time.time() - 86400, limit=1000):
            for r in e["reasons"]:
                if r["detector"] == "schema":
                    kinds.update(part.split(":")[0] for part in r["detail"].split("; "))
        return JSONResponse({"loaded": engine.schema is not None, "findings_24h": dict(kinds),
                             "endpoints": engine.schema.summary() if engine.schema else []})

    # --- threat intel and bots (wafgw/intel.py, wafgw/bot.py) ----------------------------------------
    def need_intel():
        if engine.intel is None:
            raise ValueError("threat intel is disabled ([intel] enabled = false in waf.toml)")
        return engine.intel

    async def intel_status(request):
        i, hits = need_intel(), Counter()
        for e in store.events(since=time.time() - 86400, limit=1000):
            if any(r["detector"] == "intel" for r in e["reasons"]):
                hits[e["client_ip"]] += 1
        return JSONResponse({**i.status(), "hits_24h": sum(hits.values()), "top_hits": hits.most_common(5)})

    async def intel_import(request):
        d = await request.json()
        return JSONResponse(need_intel().save(d["kind"], d.get("name", ""), d["text"]))

    async def intel_export(request):
        q = request.query_params
        try:
            return PlainTextResponse(need_intel().export(q["kind"], q.get("name", "")))
        except KeyError:
            return JSONResponse({"error": "not found"}, 404)

    async def intel_delete(request):
        if not need_intel().delete(request.path_params["kind"], request.path_params["name"]):
            return JSONResponse({"error": "not found"}, 404)
        return JSONResponse(need_intel().status())

    async def intel_lookup(request):
        return JSONResponse(need_intel().lookup(request.query_params["ip"]))

    async def intel_policy(request):
        i = need_intel()
        if request.method == "POST":
            d = await request.json()
            i.set_policy(d.get("country_deny"), d.get("asn_deny"))
            store.put("intel_policy", {"country_deny": sorted(i.country_deny), "asn_deny": sorted(i.asn_deny)})
        return JSONResponse({"country_deny": sorted(i.country_deny), "asn_deny": sorted(i.asn_deny)})

    async def bots(request):
        """Clients the bot detector fired on in the last 24 h, with their request rhythm (gaps between requests)."""
        floor = float(request.query_params.get("min_strength", 0.25))   # a lone "scripting client" (0.15) is not worth a row
        by_ip = defaultdict(list)
        for e in store.events(since=time.time() - 86400, limit=1000):
            by_ip[e["client_ip"]].append(e)
        rows = []
        for ip, v in by_ip.items():
            hits = [r for e in v for r in e["reasons"] if r["detector"] == "bot"]
            if not hits:
                continue
            if max(r["strength"] for r in hits) < floor:
                continue
            ts = sorted(e["ts"] for e in v)
            kinds = Counter(part.split(":")[0] for r in hits for part in r["detail"].split("; "))
            rows.append({"ip": ip, "requests": len(v), "bot_events": len(hits), "max_strength": round(max(r["strength"] for r in hits), 2),
                         "kinds": kinds.most_common(4), "gaps": [round(b - a, 2) for a, b in zip(ts, ts[1:])][-40:], "last_ts": ts[-1]})
        return JSONResponse({"rows": sorted(rows, key=lambda r: (-r["max_strength"], -r["bot_events"]))[:50]})

    def leak_view(e: dict) -> dict:
        return {k: e[k] for k in ("id", "ts", "client_ip", "method", "path", "upstream_status", "action", "risk", "response_flags")} | \
               {"reasons": [r for r in e["reasons"] if r["detector"] in ("response", "honeypot", "canary_used")]}

    def leak_settings() -> dict:
        g = getattr(engine, "guards", None)
        if g is None:
            return {"response": {}, "honeypots": {}}
        r, h = g.settings(), g.honeypots.settings()
        return {"response": {"enabled": r["enabled"], "action": r["action"]},
                "honeypots": {"enabled": h["enabled"], "ban_minutes": h["ban_minutes"], "canary": h["canary"], "paths": h["paths"]}}

    async def leaks(request):
        """Response leaks and honeypot / canary hits of the last 24 h, plus the current settings."""
        kinds, leaks_, hits = Counter(), [], []
        for e in store.events(since=time.time() - 86400, limit=1000, traps=True):
            kinds.update(f["kind"] for f in e["response_flags"])
            if e["response_flags"]:
                leaks_.append(leak_view(e))
            if any(r["detector"] in ("honeypot", "canary_used") for r in e["reasons"]):
                hits.append(leak_view(e))
        return JSONResponse({"settings": leak_settings(), "kinds": dict(kinds), "leaks": len(leaks_),
                             "honeypot_hits": sum(h["reasons"][0]["detector"] == "honeypot" for h in hits if h["reasons"]),
                             "canary_hits": sum(h["reasons"][0]["detector"] == "canary_used" for h in hits if h["reasons"]),
                             "recent_leaks": leaks_[:50], "recent_hits": hits[:50]})

    async def leaks_settings(request):
        d, g = await request.json(), getattr(engine, "guards", None)
        if g is None:
            raise ValueError("gateway guards are not running")
        r, h = d.get("response", {}), d.get("honeypots", {})
        if "action" in r and r["action"] not in ("alert", "redact", "block"):
            raise ValueError("response action must be alert, redact or block")
        if "ban_minutes" in h and not 0 <= int(h["ban_minutes"]) <= 10080:
            raise ValueError("ban_minutes must be 0-10080")
        store.put("response", {**(store.get("response") or {}), **{k: r[k] for k in ("enabled", "action") if k in r}})
        store.put("honeypots", {**(store.get("honeypots") or {}), **{k: h[k] for k in ("enabled", "ban_minutes", "canary") if k in h}})
        g.refresh()
        return JSONResponse(leak_settings())

    return Starlette(routes=[
        *incident_routes(engine, store, cfg, guarded),
        Route("/api/leaks", guarded(leaks)),
        Route("/api/leaks/settings", guarded(leaks_settings), methods=["POST"]),
        Route("/api/reload", guarded(reload), methods=["POST"]),
        Route("/api/intel", guarded(intel_status)),
        Route("/api/intel/import", guarded(intel_import), methods=["POST"]),
        Route("/api/intel/export", guarded(intel_export)),
        Route("/api/intel/lookup", guarded(intel_lookup)),
        Route("/api/intel/policy", guarded(intel_policy), methods=["GET", "POST"]),
        Route("/api/intel/{kind}/{name}", guarded(intel_delete), methods=["DELETE"]),
        Route("/api/bots", guarded(bots)),
        Route("/api/schema", guarded(schema)),
        Route("/api/events/{id:int}", guarded(one_event)),
        Route("/api/feedback", guarded(feedback), methods=["GET", "POST"]),
        Route("/api/exemptions", guarded(exemptions), methods=["GET", "POST"]),
        Route("/api/exemptions/{id:int}", guarded(exemptions), methods=["DELETE"]),
        Route("/api/routes", guarded(routes), methods=["GET", "POST"]),
        Route("/api/audit", guarded(audit)),
        Route("/api/settings/{key}", guarded(setting), methods=["GET", "POST"]),
        Route("/api/policy", guarded(policy), methods=["GET", "POST"]),
        Route("/api/health", health),
        Route("/api/stats", guarded(stats)),
        Route("/api/events", guarded(events)),
        Route("/api/mode", guarded(mode), methods=["GET", "POST"]),
        Route("/api/lists", guarded(lists), methods=["GET", "POST"]),
        Route("/api/lists/{ip}", guarded(lists), methods=["DELETE"]),
    ])
