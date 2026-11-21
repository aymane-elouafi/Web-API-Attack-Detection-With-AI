"""The reverse proxy: read the request, ask the engine, then forward it, block it, and log it."""
import asyncio
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
from wafgw.guard import Guards
from wafgw.honeypot import CANARY_RISK, HONEYPOT_RISK
from wafgw.store import Store, redact

HOP = {b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization", b"te", b"trailers",
       b"transfer-encoding", b"upgrade"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
BLOCK_HTML = """<!doctype html><meta charset=utf-8><title>Request blocked</title>
<body style="font:16px system-ui;max-width:32rem;margin:15vh auto;padding:0 1rem">
<h1>Request blocked</h1><p>This request was blocked by the web application firewall.</p>
<p>Reference: <code>{rid}</code></p></body>"""


def reject_websockets(app):
    """The gateway inspects plain HTTP only. Proxying a WebSocket would bypass inspection, so refuse it clearly."""
    async def wrapper(scope, receive, send):
        if scope["type"] == "websocket":
            if "websocket.http.response" in scope.get("extensions", {}):
                await send({"type": "websocket.http.response.start", "status": 501,
                            "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "websocket.http.response.body", "body": b"WebSocket is not supported by this gateway"})
            else:
                await send({"type": "websocket.close", "code": 1013})
            return
        await app(scope, receive, send)
    return wrapper


def _forward_headers(request: Request, ip: str, rid: str) -> list[tuple[bytes, bytes]]:
    raw = request.headers.raw
    listed = {t.strip().lower() for k, v in raw if k == b"connection" for t in v.split(b",")}
    out = [(k, v) for k, v in raw if k not in HOP and k not in listed and k not in (b"content-length", b"x-waf-request-id")]
    prior = request.headers.get("x-forwarded-for")
    return out + [(b"x-forwarded-for", f"{prior}, {ip}".encode() if prior else ip.encode()),
                  (b"x-forwarded-proto", request.url.scheme.encode()),
                  (b"x-forwarded-host", request.headers.get("host", "").encode()),
                  (b"x-waf-request-id", rid.encode())]


def build_app(cfg: dict, engine: Engine, store: Store, client: httpx.AsyncClient | None = None,
              coraza_client: httpx.AsyncClient | None = None) -> Starlette:
    p = cfg["proxy"]
    upstream = p["upstream"].rstrip("/")
    state = {"client": client, "coraza": coraza_client}
    cz = cfg["coraza"]
    guards = engine.guards = Guards(cfg, store)               # response leak scan + honeypots (the admin API reads them too)
    hp = guards.honeypots

    async def ask_coraza(request: Request, raw_path: str, query: str, body: bytes, ip: str, rid: str) -> dict:
        """Send a copy of the request to the Coraza+CRS side-car (INSPECT_ONLY=1) BEFORE forwarding, read its verdict headers."""
        if state["coraza"] is None:
            state["coraza"] = httpx.AsyncClient(timeout=cz["timeout_s"])
        url = cz["url"].rstrip("/") + raw_path + (f"?{query}" if query else "")
        try:
            r = await state["coraza"].send(state["coraza"].build_request(
                request.method, url, headers=_forward_headers(request, ip, rid), content=body))
            return {"score": int(r.headers.get("x-waf-score", 0)), "rules": r.headers.get("x-waf-rules", "")}
        except (httpx.HTTPError, ValueError) as exc:        # side-car down: keep protecting with the other detectors
            return {"score": 0, "rules": "", "error": f"coraza unavailable ({type(exc).__name__})"}

    def blocked(v: Verdict, rid: str, request: Request) -> Response:
        headers = {"x-waf-request-id": rid, "cache-control": "no-store"}
        if v.status == 429:
            headers["retry-after"] = "1"
        wants_json = "json" in request.headers.get("accept", "") or request.url.path.startswith("/api")
        if wants_json:
            return JSONResponse({"error": "blocked", "request_id": rid}, v.status, headers)
        return HTMLResponse(BLOCK_HTML.format(rid=rid), v.status, headers)

    def log(request: Request, info: dict, rid: str, v: Verdict, status: int, action: str, extra: dict | None = None) -> None:
        store.log({"ts": info["ts"], "request_id": rid, "client_ip": info["client_ip"], "method": info["method"],
                   "host": request.headers.get("host", ""), "path": info["path"],
                   "query": redact(info["query"], 1024), "user_agent": info["user_agent"][:256],
                   "body_snippet": redact(info["body"]), "upstream_status": status, "action": action,
                   "risk": round(v.risk, 4), "detectors": json.dumps({k: round(x, 4) for k, x in v.detectors.items()}),
                   "reasons": json.dumps(v.reasons), "latency_ms": round(v.latency_ms, 3), "route": v.route, **(extra or {})})

    def ban(ip: str, mode: str, why: str) -> None:
        minutes = hp.settings()["ban_minutes"]
        if mode == "block" and minutes and not store.listed(ip, "allow"):
            store.add_list(ip, "deny", why, ttl_s=minutes * 60)     # block mode only: monitor mode never changes traffic

    def honeypot(request: Request, info: dict, rid: str, mode: str) -> Response:
        """Answer a honeypot path with a fake (never forwarded). A real user never asks for these paths."""
        reasons = [{"detector": "honeypot", "score": 1, "strength": HONEYPOT_RISK, "detail": f"{info['method']} {info['path']}"}]
        log(request, info, rid, Verdict(HONEYPOT_RISK, "block", reasons, route="honeypot"), 200, "blocked")
        ban(info["client_ip"], mode, f"honeypot {info['path']}")
        ctype, content = hp.fake(info["path"])
        return Response(content, 200, media_type=ctype, headers={"x-waf-request-id": rid, "cache-control": "no-store"})

    def canary(v: Verdict, request: Request, info: dict, mode: str) -> Verdict:
        """A fake credential from a honeypot came back in a request: someone is using what they stole."""
        text = " ".join([request.headers.get("authorization", ""), request.headers.get("cookie", ""), info["query"], info["body"]])
        kind = hp.canary_used(text)
        if not kind:
            return v
        ban(info["client_ip"], mode, f"canary {kind}")
        reasons = [{"detector": "canary_used", "score": 1, "strength": CANARY_RISK, "detail": f"{kind} canary presented"}] + v.reasons
        return Verdict(CANARY_RISK, "block" if mode == "block" else "monitor", reasons, v.latency_ms, 403, v.route)

    async def handle(request: Request) -> Response:
        rid = uuid.uuid4().hex[:12]
        if request.headers.get("upgrade", "").lower() == "websocket":
            return JSONResponse({"error": "websocket not supported", "request_id": rid}, 501)
        declared = request.headers.get("content-length") or "0"
        if not declared.isdigit():
            return JSONResponse({"error": "invalid content-length", "request_id": rid}, 400)
        if int(declared) > p["max_body_bytes"]:
            return JSONResponse({"error": "request body too large", "request_id": rid}, 413)
        chunks, size = [], 0

        async def read_body() -> bool:
            nonlocal size
            async for chunk in request.stream():
                size += len(chunk)
                if size > p["max_body_bytes"]:
                    return False
                chunks.append(chunk)
            return True

        try:
            fits = await asyncio.wait_for(read_body(), p["body_timeout_s"])   # slow-body (slowloris-style) clients
        except asyncio.TimeoutError:
            return JSONResponse({"error": "request body timeout", "request_id": rid}, 408)
        if not fits:
            return JSONResponse({"error": "request body too large", "request_id": rid}, 413)
        body = b"".join(chunks)

        peer = request.client.host if request.client else "0.0.0.0"
        xff = request.headers.get("x-forwarded-for", "")
        ip = xff.split(",")[0].strip() if p["trust_forwarded"] and xff else peer
        raw_path = request.scope.get("raw_path", request.url.path.encode()).decode("latin-1")
        query = request.scope["query_string"].decode("latin-1")
        info = {"method": request.method, "path": request.url.path, "query": query, "ts": time.time(),
                "body": body.decode("utf-8", "replace"), "user_agent": request.headers.get("user-agent", ""),
                "client_ip": ip, "session": session_id(request.headers), "headers": request.headers.raw, "http_version": request.scope.get("http_version", "1.1")}

        mode = engine.route_for(info["path"]).get("mode", engine.mode)
        if hp.match(info["path"]) and not store.listed(ip, "deny"):
            return honeypot(request, info, rid, mode)
        if cz["enabled"]:
            info["coraza"] = await ask_coraza(request, raw_path, query, body, ip, rid)
        try:
            v = engine.inspect(info)
        except Exception as exc:                                  # a bug in a detector must not take the site down
            v = Verdict(0.0, "allow", [{"detector": "engine", "score": 0, "strength": 0, "detail": f"error: {type(exc).__name__}"}])
            if cfg["engine"]["on_error"] == "fail_closed":
                log(request, info, rid, v, 503, "blocked")
                return JSONResponse({"error": "service unavailable", "request_id": rid}, 503)

        v = canary(v, request, info, mode)
        if v.action == "block":
            log(request, info, rid, v, v.status, "blocked")
            return blocked(v, rid, request)

        if state["client"] is None:
            state["client"] = httpx.AsyncClient(timeout=p["upstream_timeout_s"], follow_redirects=False)
        url = upstream + raw_path + (f"?{query}" if query else "")
        req = state["client"].build_request(request.method, url, headers=guards.upstream_headers(_forward_headers(request, ip, rid)), content=body)
        try:
            resp = await state["client"].send(req, stream=True)
        except httpx.TimeoutException:
            log(request, info, rid, v, 504, "would_block" if v.action == "monitor" else "allowed")
            return JSONResponse({"error": "upstream timeout", "request_id": rid}, 504)
        except httpx.HTTPError:
            log(request, info, rid, v, 502, "would_block" if v.action == "monitor" else "allowed")
            return JSONResponse({"error": "bad gateway", "request_id": rid}, 502)

        engine.observe(info, resp.status_code)
        g = await guards.inspect(resp, info["path"], mode, request.method)
        extra = guards.event_fields(g, v.reasons)
        if g["outcome"] == "blocked":                             # leak found, nothing was sent to the client yet
            await resp.aclose()
            log(request, info, rid, v, 502, "blocked", extra)
            return JSONResponse({"error": "response blocked", "request_id": rid}, 502, {"x-waf-request-id": rid, "cache-control": "no-store"})
        log(request, info, rid, v, resp.status_code, "would_block" if v.action == "monitor" else "allowed", extra)
        headers = [(k, val) for k, val in resp.headers.raw if k.lower() not in HOP | {b"date", b"server"}]
        tail = [(b"x-waf-request-id", rid.encode())]
        if g["body"] is not None:                                 # small text answer, already read: send it in one piece
            await resp.aclose()
            out = Response(g["body"], resp.status_code)
            out.raw_headers = [(k, val) for k, val in headers if k.lower() != b"content-length"] + [(b"content-length", str(len(g["body"])).encode())] + tail
            return out
        out = StreamingResponse(g["stream"], resp.status_code, background=BackgroundTask(resp.aclose))
        out.raw_headers = headers + tail
        return out

    @contextlib.asynccontextmanager
    async def lifespan(app):
        yield
        if state["client"] is not None and client is None:
            await state["client"].aclose()
        if state["coraza"] is not None and coraza_client is None:
            await state["coraza"].aclose()

    return reject_websockets(Starlette(routes=[Route("/{path:path}", handle, methods=METHODS)], lifespan=lifespan))
