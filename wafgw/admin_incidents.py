"""Admin routes for incidents, the optional LLM explainer and reports (kept out of admin.py so that file stays small).

GET  /api/incidents?since=&until=&gap=&limit=   incidents, most severe first (no timeline; open one for the full story)
GET  /api/incidents/{id}                       one incident: timeline, write-up, OWASP/CWE/ATT&CK references, actions
POST /api/incidents/{id}/narrative             LLM paragraph; 403 unless [explainer] enabled
GET  /api/explainer                            {enabled, model, format, sends_ip, endpoint_host} (never the key)
GET  /api/report?since=&until=|window_h=       the JSON report
GET  /api/reports                              files written so far;  POST: write one now (and send it to the webhook if configured)
GET  /api/reports/{name}                       a generated .html / .json file
"""
import asyncio
import re
import time
from pathlib import Path

import httpx
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from wafgw import explainer, incidents, report

REPORTS = {"enabled": False, "dir": "data/reports", "every_h": 24, "window_h": 24, "webhook": False}
FILE = re.compile(r"^[\w.-]+\.(html|json)$")
LIGHT_DROP = ("timeline", "narrative", "recommendations")


def routes(engine, store, cfg: dict | None, guarded) -> list[Route]:
    cfg = cfg or {}
    rep = {**REPORTS, **cfg.get("reports", {})}
    ex_cfg = {**explainer.DEFAULTS, **cfg.get("explainer", {})}
    info = lambda: {"mode": engine.mode, "threshold": engine.threshold,
                    "models": {"payload": engine.payload is not None, "behavior": engine.behavior is not None, "schema": engine.schema is not None}}

    def window(q) -> tuple[float, float]:
        until = float(q.get("until", time.time()))
        return float(q["since"]) if "since" in q else until - 3600 * float(q.get("window_h", 24)), until

    def context(gap):
        return lambda ip, a, b: store.events(ip=ip, since=a - 1, until=b + gap, limit=1000)

    def incident_by_id(event_id: int, gap: float = incidents.GAP_S) -> dict | None:
        ev = store.event(event_id)
        if ev is None:
            return None
        flagged = [e for e in store.events(ip=ev["client_ip"], since=ev["ts"] - 1, flagged=True, limit=5000) if e["ts"] >= ev["ts"]]
        run = next((r for r in incidents.group(flagged, gap) if r[0]["id"] == event_id), None)
        return incidents.build_incident(ev["client_ip"], run, context(gap)(ev["client_ip"], run[0]["ts"], run[-1]["ts"])) if run else None

    async def incidents_list(request):
        q = request.query_params
        since, until = window(q)
        gap, limit = float(q.get("gap", incidents.GAP_S)), min(int(q.get("limit", 100)), 500)
        def work():
            seen = [0]
            def ctx(ip, a, b):
                seen[0] += 1
                return context(gap)(ip, a, b) if seen[0] <= 100 else None
            return incidents.build_all(store.flagged(since, until, 8000), gap, ctx, limit)
        found = await asyncio.to_thread(work)
        return JSONResponse({"since": since, "until": until, "incidents": [{k: v for k, v in i.items() if k not in LIGHT_DROP} for i in found]})

    async def incident_one(request):
        found = await asyncio.to_thread(incident_by_id, int(request.path_params["id"]))
        return JSONResponse(found) if found else JSONResponse({"error": "not found"}, 404)

    async def narrative(request):
        found = await asyncio.to_thread(incident_by_id, int(request.path_params["id"]))
        if found is None:
            return JSONResponse({"error": "not found"}, 404)
        try:
            return JSONResponse(await explainer.narrate(found, ex_cfg))
        except PermissionError as exc:
            return JSONResponse({"error": str(exc)}, 403)
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            return JSONResponse({"error": f"the explainer endpoint failed: {type(exc).__name__}"}, 502)

    async def explainer_status(request):
        return JSONResponse(explainer.status(ex_cfg))

    async def report_json(request):
        since, until = window(request.query_params)
        return JSONResponse(await asyncio.to_thread(report.build_report, store, since, until, info()))

    async def reports(request):
        if request.method == "POST":
            until = time.time()
            built = await asyncio.to_thread(report.build_report, store, until - 3600 * rep["window_h"], until, info())
            path = await asyncio.to_thread(report.write_files, built, rep["dir"])
            sent = await report.deliver(store, built, path) if rep["webhook"] else "webhook delivery is off"
            return JSONResponse({"path": path, "summary": built["summary"], "delivery": sent})
        return JSONResponse({"dir": rep["dir"], "schedule": {k: rep[k] for k in ("enabled", "every_h", "window_h", "webhook")}, "files": report.list_files(rep["dir"])})

    async def report_file(request):
        name = request.path_params["name"]
        if not FILE.match(name):
            return JSONResponse({"error": "bad file name"}, 400)
        path = Path(rep["dir"]) / name
        if not path.is_file():
            return JSONResponse({"error": "not found"}, 404)
        return Response(path.read_text(), media_type="text/html" if name.endswith(".html") else "application/json")

    return [Route("/api/incidents", guarded(incidents_list)), Route("/api/incidents/{id:int}", guarded(incident_one)),
            Route("/api/incidents/{id:int}/narrative", guarded(narrative), methods=["POST"]),
            Route("/api/explainer", guarded(explainer_status)), Route("/api/report", guarded(report_json)),
            Route("/api/reports", guarded(reports), methods=["GET", "POST"]), Route("/api/reports/{name}", guarded(report_file))]
