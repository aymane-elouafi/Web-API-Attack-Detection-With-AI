"""Gateway tests: real proxy + engine + store against a fake upstream, no network.   Run:  python -m unittest discover -s tests -t ."""
import tempfile
import unittest

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from wafgw import config
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.proxy import build_app
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
        app = build_app(self.cfg, self.engine, self.store, client=self.upstream)
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


class RedactTests(unittest.TestCase):
    def test_redact(self):
        self.assertEqual(redact('{"password": "x y", "name": "bo"}'), '{"password": "***", "name": "bo"}')
        self.assertEqual(redact("a=1&token=abc&b=2"), "a=1&token=***&b=2")
        self.assertEqual(len(redact("z" * 5000)), 2048)


if __name__ == "__main__":
    unittest.main()
