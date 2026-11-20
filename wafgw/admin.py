"""Admin API (separate port, bearer token). This is the contract the dashboard talks to; see wafgw/README.md."""
import hmac
import ipaddress
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

START = time.time()
SETTING_KEYS = {"alerts"}


def build_admin(engine, store, token: str | None) -> Starlette:
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
                             "models": {"payload": engine.payload is not None, "behavior": engine.behavior is not None}})

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

    return Starlette(routes=[
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
