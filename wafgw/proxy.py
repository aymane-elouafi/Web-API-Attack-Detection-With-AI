"""The reverse proxy: read the request, ask the engine, then forward it, block it, and log it."""
import contextlib
import json
import time
import uuid

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from wafgw.engine import Engine, Verdict, session_id
from wafgw.store import Store, redact

HOP = {b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization", b"te", b"trailers",
       b"transfer-encoding", b"upgrade"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
BLOCK_HTML = """<!doctype html><meta charset=utf-8><title>Request blocked</title>
<body style="font:16px system-ui;max-width:32rem;margin:15vh auto;padding:0 1rem">
<h1>Request blocked</h1><p>This request was blocked by the web application firewall.</p>
<p>Reference: <code>{rid}</code></p></body>"""


def _forward_headers(request: Request, ip: str, rid: str) -> list[tuple[bytes, bytes]]:
    raw = request.headers.raw
    listed = {t.strip().lower() for k, v in raw if k == b"connection" for t in v.split(b",")}
    out = [(k, v) for k, v in raw if k not in HOP and k not in listed and k not in (b"content-length", b"x-waf-request-id")]
    prior = request.headers.get("x-forwarded-for")
    return out + [(b"x-forwarded-for", f"{prior}, {ip}".encode() if prior else ip.encode()),
                  (b"x-forwarded-proto", request.url.scheme.encode()),
                  (b"x-forwarded-host", request.headers.get("host", "").encode()),
                  (b"x-waf-request-id", rid.encode())]


def build_app(cfg: dict, engine: Engine, store: Store, client: httpx.AsyncClient | None = None) -> Starlette:
    p = cfg["proxy"]
    upstream = p["upstream"].rstrip("/")
    state = {"client": client}

    def blocked(v: Verdict, rid: str, request: Request) -> Response:
        headers = {"x-waf-request-id": rid, "cache-control": "no-store"}
        if v.status == 429:
            headers["retry-after"] = "1"
        wants_json = "json" in request.headers.get("accept", "") or request.url.path.startswith("/api")
        if wants_json:
            return JSONResponse({"error": "blocked", "request_id": rid}, v.status, headers)
        return HTMLResponse(BLOCK_HTML.format(rid=rid), v.status, headers)

    def log(request: Request, info: dict, rid: str, v: Verdict, status: int, action: str) -> None:
        store.log({"ts": info["ts"], "request_id": rid, "client_ip": info["client_ip"], "method": info["method"],
                   "host": request.headers.get("host", ""), "path": info["path"],
                   "query": redact(info["query"], 1024), "user_agent": info["user_agent"][:256],
                   "body_snippet": redact(info["body"]), "upstream_status": status, "action": action,
                   "risk": round(v.risk, 4), "detectors": json.dumps({k: round(x, 4) for k, x in v.detectors.items()}),
                   "reasons": json.dumps(v.reasons), "latency_ms": round(v.latency_ms, 3), "route": v.route})

    async def handle(request: Request) -> Response:
        rid = uuid.uuid4().hex[:12]
        if int(request.headers.get("content-length") or 0) > p["max_body_bytes"]:
            return JSONResponse({"error": "request body too large", "request_id": rid}, 413)
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > p["max_body_bytes"]:
                return JSONResponse({"error": "request body too large", "request_id": rid}, 413)
            chunks.append(chunk)
        body = b"".join(chunks)

        peer = request.client.host if request.client else "0.0.0.0"
        xff = request.headers.get("x-forwarded-for", "")
        ip = xff.split(",")[0].strip() if p["trust_forwarded"] and xff else peer
        raw_path = request.scope.get("raw_path", request.url.path.encode()).decode("latin-1")
        query = request.scope["query_string"].decode("latin-1")
        info = {"method": request.method, "path": request.url.path, "query": query, "ts": time.time(),
                "body": body.decode("utf-8", "replace"), "user_agent": request.headers.get("user-agent", ""),
                "client_ip": ip, "session": session_id(request.headers)}

        try:
            v = engine.inspect(info)
        except Exception as exc:                                  # a bug in a detector must not take the site down
            v = Verdict(0.0, "allow", [{"detector": "engine", "score": 0, "strength": 0, "detail": f"error: {type(exc).__name__}"}])
            if cfg["engine"]["on_error"] == "fail_closed":
                log(request, info, rid, v, 503, "blocked")
                return JSONResponse({"error": "service unavailable", "request_id": rid}, 503)

        if v.action == "block":
            log(request, info, rid, v, v.status, "blocked")
            return blocked(v, rid, request)

        if state["client"] is None:
            state["client"] = httpx.AsyncClient(timeout=p["upstream_timeout_s"], follow_redirects=False)
        url = upstream + raw_path + (f"?{query}" if query else "")
        req = state["client"].build_request(request.method, url, headers=_forward_headers(request, ip, rid), content=body)
        try:
            resp = await state["client"].send(req, stream=True)
        except httpx.TimeoutException:
            log(request, info, rid, v, 504, "would_block" if v.action == "monitor" else "allowed")
            return JSONResponse({"error": "upstream timeout", "request_id": rid}, 504)
        except httpx.HTTPError:
            log(request, info, rid, v, 502, "would_block" if v.action == "monitor" else "allowed")
            return JSONResponse({"error": "bad gateway", "request_id": rid}, 502)

        engine.observe(info, resp.status_code)
        log(request, info, rid, v, resp.status_code, "would_block" if v.action == "monitor" else "allowed")
        out = StreamingResponse(resp.aiter_raw(), resp.status_code, background=BackgroundTask(resp.aclose))
        out.raw_headers = [(k, val) for k, val in resp.headers.raw if k.lower() not in HOP | {b"date", b"server"}] + [(b"x-waf-request-id", rid.encode())]
        return out

    @contextlib.asynccontextmanager
    async def lifespan(app):
        yield
        if state["client"] is not None and client is None:
            await state["client"].aclose()

    return Starlette(routes=[Route("/{path:path}", handle, methods=METHODS)], lifespan=lifespan)
