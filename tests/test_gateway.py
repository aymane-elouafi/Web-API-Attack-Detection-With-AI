"""Gateway tests: real proxy + engine + store against a fake upstream, no network.   Run:  python -m unittest discover -s tests -t ."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from detection.schema import SchemaModel
from wafgw import config
from wafgw.__main__ import proxy_config
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.proxy import build_app
from traffic.replay import load_sessions, schedule
from wafgw.store import Store, redact

SQLI = "/products/search?q=%27%20OR%201%3D1%20--"


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.seen = []
        async def echo(request):
            self.seen.append(dict(request.headers) | {"path": request.url.path})
            return JSONResponse({"ok": True}, 401 if request.url.path == "/login" else 200)
        self.upstream = httpx.AsyncClient(transport=httpx.ASGITransport(Starlette(routes=[Route("/{p:path}", echo, methods=["GET", "POST"])])),
                                          base_url="http://upstream")
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = config.load("/nonexistent.toml")
        self.cfg["proxy"]["upstream"] = "http://upstream"
        self.cfg["store"]["path"] = f"{self.tmp.name}/waf.db"
        self.cfg["engine"]["mode"] = "block"

    async def asyncTearDown(self):
        await self.upstream.aclose()
        self.tmp.cleanup()

    def gateway(self, ip="9.9.9.9"):
        self.store = Store(self.cfg["store"]["path"])
        self.engine = Engine(self.cfg, self.store)
        self.app = app = build_app(self.cfg, self.engine, self.store, client=self.upstream)
        return httpx.AsyncClient(transport=httpx.ASGITransport(app, client=(ip, 1234)), base_url="http://gw")

    def events(self):
        self.store.flush()
        return self.store.events()

    async def test_benign_request_is_forwarded_and_logged(self):
        async with self.gateway() as gw:
            r = await gw.get("/products/search?q=laptop")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["x-waf-request-id"])
        self.assertEqual(self.seen[0]["x-forwarded-for"], "9.9.9.9")
        self.assertEqual(self.events()[0]["action"], "allowed")

    async def test_block_mode_stops_sql_injection_before_the_application(self):
        async with self.gateway() as gw:
            r = await gw.get(SQLI)
        self.assertEqual(r.status_code, 403)
        self.assertIn(r.headers["x-waf-request-id"], r.text)
        self.assertEqual(self.seen, [])
        e = self.events()[0]
        self.assertEqual((e["action"], e["upstream_status"]), ("blocked", 403))
        self.assertGreaterEqual(e["risk"], 0.5)
        self.assertIn("rules", e["detectors"])

    async def test_monitor_mode_forwards_but_records_would_block(self):
        self.cfg["engine"]["mode"] = "monitor"
        async with self.gateway() as gw:
            r = await gw.get(SQLI)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(self.events()[0]["action"], "would_block")

    async def test_deny_list_blocks_and_allow_list_skips_inspection(self):
        async with self.gateway("1.2.3.4") as gw:
            self.store.add_list("1.2.3.0/24", "deny")
            self.assertEqual((await gw.get("/products/search?q=laptop")).status_code, 403)
            self.store.add_list("1.2.3.4", "allow")      # the allow list is checked before the deny list
            self.store.remove_list("1.2.3.0/24")
            self.assertEqual((await gw.get(SQLI)).status_code, 200)

    async def test_rate_limit_answers_429(self):
        self.cfg["rate_limit"] = {"enabled": True, "rate_per_s": 0.001, "burst": 3}
        async with self.gateway() as gw:
            codes = [(await gw.get("/products/1")).status_code for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])

    async def test_engine_crash_fails_open_or_closed(self):
        for policy, expected in [("fail_open", 200), ("fail_closed", 503)]:
            self.cfg["engine"]["on_error"] = policy
            async with self.gateway() as gw:
                self.engine.inspect = lambda info: 1 / 0
                self.assertEqual((await gw.get("/products/1")).status_code, expected)

    async def test_secrets_are_redacted_in_the_event_log(self):
        async with self.gateway() as gw:
            await gw.post("/login", json={"username": "ann", "password": "Secret1!"})
            await gw.get("/products/1?api_key=abc123xyz")
        rows = self.events()
        text = " ".join(f"{r['body_snippet']} {r['query']}" for r in rows)
        self.assertNotIn("Secret1!", text)
        self.assertNotIn("abc123xyz", text)
        self.assertIn("ann", text)

    async def test_admin_needs_a_token_and_serves_stats(self):
        self.gateway()
        with self.assertRaises(RuntimeError):
            build_admin(self.engine, self.store, None)
        admin = httpx.AsyncClient(transport=httpx.ASGITransport(build_admin(self.engine, self.store, "s3cret")), base_url="http://a")
        async with admin:
            self.assertEqual((await admin.get("/api/stats")).status_code, 401)
            r = await admin.get("/api/stats", headers={"authorization": "Bearer s3cret"})
            self.assertEqual(r.json()["mode"], "block")
            r = await admin.post("/api/mode", json={"mode": "monitor"}, headers={"authorization": "Bearer s3cret"})
            self.assertEqual(r.json()["mode"], "monitor")

    async def test_websocket_upgrade_is_refused_clearly(self):
        async with self.gateway() as gw:
            r = await gw.get("/ws", headers={"upgrade": "websocket", "connection": "Upgrade"})
        self.assertEqual(r.status_code, 501)
        self.assertEqual(self.seen, [])
        sent = []
        async def send(m): sent.append(m)
        async def receive(): return {"type": "websocket.connect"}
        scope = {"type": "websocket", "path": "/ws", "headers": [], "extensions": {"websocket.http.response": {}}}
        await self.app(scope, receive, send)
        self.assertEqual(sent[0]["status"], 501)
        sent.clear()
        await self.app({**scope, "extensions": {}}, receive, send)      # server without the HTTP-response extension
        self.assertEqual(sent, [{"type": "websocket.close", "code": 1013}])

    async def test_bad_content_length_and_slow_body(self):
        self.cfg["proxy"]["body_timeout_s"] = 0.2
        async def slow():
            yield b"a"
            await asyncio.sleep(1)
            yield b"b"
        async with self.gateway() as gw:
            self.assertEqual((await gw.get("/x", headers={"content-length": "abc"})).status_code, 400)
            self.assertEqual((await gw.post("/x", content=slow())).status_code, 408)
        self.assertEqual(self.seen, [])

    async def test_reload_endpoint_applies_a_new_schema_without_restart(self):
        models = Path(self.tmp.name) / "models"
        models.mkdir()
        self.cfg["models"]["dir"] = str(models)
        self.gateway()
        admin = httpx.AsyncClient(transport=httpx.ASGITransport(build_admin(self.engine, self.store, "t")), base_url="http://a")
        async with admin:
            self.assertFalse((await admin.get("/api/health")).json()["models"]["schema"])
            shop = [("GET", f"/orders/{i}", "", "") for i in range(1, 30)]
            (models / "schema.json").write_text(SchemaModel().learn(shop).to_json())
            r = await admin.post("/api/reload", headers={"authorization": "Bearer t"})
            self.assertEqual(r.json()["reloaded"], ["schema"])
            self.assertTrue((await admin.get("/api/health")).json()["models"]["schema"])
            self.assertEqual((await admin.post("/api/reload")).status_code, 401)


class ReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = config.load("/nonexistent.toml")
        self.cfg["models"]["dir"] = self.tmp.name
        self.file = Path(self.tmp.name) / "schema.json"
        self.good = SchemaModel().learn([("GET", f"/orders/{i}", "", "") for i in range(1, 30)]).to_json()

    def tearDown(self):
        self.tmp.cleanup()

    def test_changed_broken_and_fixed_model_file(self):
        engine = Engine(self.cfg)
        self.assertIsNone(engine.schema)
        self.file.write_text(self.good)
        self.assertEqual(engine.reload_models(), ["schema"])
        self.file.write_text("{not json")
        self.assertEqual(engine.reload_models(), [])
        self.assertIn("schema.json", engine.reload_errors)
        self.assertIsNotNone(engine.schema)                       # the old model keeps running
        self.file.write_text(self.good + " ")
        self.assertEqual(engine.reload_models(), ["schema"])
        self.assertEqual(engine.reload_errors, {})

    def test_requests_pick_up_a_new_model_file_on_their_own(self):
        engine = Engine(self.cfg)
        self.file.write_text(self.good)
        engine._next_check = 0                                    # the periodic check is due
        info = dict(method="GET", path="/admin", query="", body="", user_agent="", client_ip="1.1.1.1", session="", ts=1.0)
        v = engine.inspect(info)
        self.assertIn("schema", v.detectors)


class TlsConfigTests(unittest.TestCase):
    def test_tls_settings_reach_uvicorn_and_are_validated(self):
        cfg = config.load("/nonexistent.toml")
        self.assertIsNone(proxy_config(cfg, None).ssl_certfile)
        with tempfile.NamedTemporaryFile() as cert, tempfile.NamedTemporaryFile() as key:
            cfg["tls"] = {"cert": cert.name, "key": key.name}
            self.assertEqual(proxy_config(cfg, None).ssl_certfile, cert.name)
            cfg["tls"] = {"cert": cert.name, "key": ""}
            with self.assertRaises(SystemExit):
                proxy_config(cfg, None)
        cfg["tls"] = {"cert": "/no/such.pem", "key": "/no/such.key"}
        with self.assertRaises(SystemExit):
            proxy_config(cfg, None)


class ReplayTests(unittest.TestCase):
    def test_sessions_keep_their_gaps_and_only_the_start_moves(self):
        rows = [(1000, "1.1.1.1"), (1001.5, "1.1.1.1"), (1003, "1.1.1.1"), (9000, "1.1.1.1"), (9000.2, "1.1.1.1"), (1200, "2.2.2.2")]
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            f.write("ts,client_ip,user,user_agent,method,path,query,body,label,attack_type\n")
            f.writelines(f"{ts},{ip},,ua,GET,/p,,,0,normal\n" for ts, ip in rows)
        sessions = load_sessions(f.name)
        self.assertEqual(sorted(map(len, sessions)), [1, 2, 3])        # a gap over 300 s ends a session
        plan = schedule(sessions, rate=1, speed=2, seed=7)
        self.assertEqual(plan, schedule(sessions, rate=1, speed=2, seed=7))      # seeded, reproducible
        three = next(steps for _, steps in plan if len(steps) == 3)
        self.assertEqual([round(o, 3) for o, _ in three], [0.0, 0.75, 1.5])       # gaps divided by --speed
        self.assertTrue(all(0 <= start <= len(rows) / 1 for start, _ in plan))   # spread over total/rate seconds
        self.assertEqual(sum(len(steps) for _, steps in plan), len(rows))
        Path(f.name).unlink()


class RedactTests(unittest.TestCase):
    def test_redact(self):
        self.assertEqual(redact('{"password": "x y", "name": "bo"}'), '{"password": "***", "name": "bo"}')
        self.assertEqual(redact("a=1&token=abc&b=2"), "a=1&token=***&b=2")
        self.assertEqual(len(redact("z" * 5000)), 2048)


if __name__ == "__main__":
    unittest.main()
