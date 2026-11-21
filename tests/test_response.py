"""Response-leak scanner, honeypots and canaries.   Run:  python -m unittest discover -s tests -t ."""
import tempfile
import unittest

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from wafgw import config
from wafgw.engine import Engine
from wafgw.proxy import build_app
from wafgw.response import SizeWatch, luhn, redact, scan, strength
from wafgw.store import Store

TRACE = "Traceback (most recent call last):\n  File \"app.py\", line 3, in view\nValueError: boom"
BODIES = {"/trace": PlainTextResponse(TRACE, 500),
          "/leak": JSONResponse({"user": "bob", "password": "hunter2hunter2", "card": "4111 1111 1111 1111"}),
          "/clean": JSONResponse({"user": "bob", "note": "it's -- fine"}),
          "/big": Response(b"x" * 600_000, media_type="text/plain"),
          "/img": Response(b"\x89PNG password=hunter2hunter2", media_type="image/png")}


class ScannerTests(unittest.TestCase):
    def test_leaks_are_found_and_clean_text_is_not(self):
        kinds = lambda t: {f["kind"] for f in scan(t)}
        self.assertEqual(kinds(TRACE), {"stack_trace"})
        self.assertIn("sql_error", kinds('{"error": "database error: near \\"x\\": syntax error"}'))
        self.assertIn("aws_key", kinds("key=AKIAIOSFODNN7EXAMPLE"))
        self.assertIn("private_key", kinds("-----BEGIN RSA PRIVATE KEY-----\nabc"))
        self.assertIn("card_number", kinds("4111 1111 1111 1111"))
        self.assertIn("iban", kinds("GB82 WEST 1234 5698 7654 32"))
        self.assertIn("bulk_emails", kinds(" ".join(f"u{i}@x.io" for i in range(6))))
        self.assertEqual(kinds('{"name": "O\'Brien", "note": "a -- b", "n": "1234 5678 9012 3456", "code": "AB12 CD34 EF56 GH78"}'), set())

    def test_luhn_and_redaction_keep_the_shape(self):
        self.assertTrue(luhn("4111111111111111") and not luhn("4111111111111112"))
        text = '{"password": "hunter2hunter2", "id": 7}'
        self.assertEqual(redact(text, scan(text)), '{"password": "[redacted]", "id": 7}')
        self.assertAlmostEqual(strength(scan(TRACE + " AKIAIOSFODNN7EXAMPLE")), 1 - 0.2 * 0.1)

    def test_size_anomaly_needs_history(self):
        w = SizeWatch()
        self.assertIsNone(w.check("/orders/1", 10_000_000))                # no history yet, no verdict
        for i in range(25):
            w.check(f"/orders/{i}", 500)
        self.assertEqual(w.check("/orders/99", 900_000)["kind"], "size_anomaly")
        self.assertIsNone(w.check("/orders/98", 600))


class GatewayLeakTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def app_(request):
            return BODIES.get(request.url.path, JSONResponse({"echo": request.url.path}))
        self.upstream = httpx.AsyncClient(transport=httpx.ASGITransport(Starlette(routes=[Route("/{p:path}", app_, methods=["GET", "POST"])])),
                                          base_url="http://upstream")
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = config.load("/nonexistent.toml")
        self.cfg["proxy"]["upstream"] = "http://upstream"
        self.cfg["store"]["path"] = f"{self.tmp.name}/waf.db"
        self.cfg["models"]["dir"] = f"{self.tmp.name}/none"                    # rules only: fast and deterministic
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

    async def test_alert_only_by_default_logs_the_leak_and_changes_nothing(self):
        async with self.gateway() as gw:
            r = await gw.get("/leak")
        self.assertIn("hunter2hunter2", r.text)                                # untouched
        e = self.events()[0]
        self.assertEqual(e["action"], "allowed")
        self.assertEqual({f["kind"] for f in e["response_flags"]}, {"secret_field", "card_number"})
        self.assertIn("response", [x["detector"] for x in e["reasons"]])
        self.assertNotIn("response", e["detectors"])                           # request-side verdict is not touched
        self.assertGreater(e["resp_bytes"], 0)

    async def test_redact_and_block_apply_in_block_mode_only(self):
        self.cfg["response"]["action"] = "redact"
        async with self.gateway() as gw:
            r = await gw.get("/leak")
            self.assertNotIn("hunter2hunter2", r.text)
            self.assertNotIn("4111", r.text)
            self.assertEqual(int(r.headers["content-length"]), len(r.content))
            self.assertEqual((await gw.get("/clean")).json()["note"], "it's -- fine")
        self.cfg["response"]["action"], self.cfg["engine"]["mode"] = "block", "monitor"
        async with self.gateway("9.9.9.8") as gw:
            self.assertEqual((await gw.get("/trace")).status_code, 500)       # monitor: alert only, never blocks
        self.cfg["engine"]["mode"] = "block"
        async with self.gateway("9.9.9.7") as gw:
            r = await gw.get("/trace")
        self.assertEqual((r.status_code, r.json()["error"]), (502, "response blocked"))
        self.assertNotIn("Traceback", r.text)
        self.assertEqual(self.events()[0]["action"], "blocked")

    async def test_big_and_binary_bodies_keep_streaming_untouched(self):
        async with self.gateway() as gw:
            big, img = await gw.get("/big"), await gw.get("/img")
        self.assertEqual(len(big.content), 600_000)
        self.assertEqual(img.content, b"\x89PNG password=hunter2hunter2")      # not an inspected type
        self.assertEqual([e["response_flags"] for e in self.events()], [[], []])

    async def test_honeypot_serves_a_fake_logs_it_and_bans_in_block_mode(self):
        async with self.gateway("6.6.6.6") as gw:
            r = await gw.get("/.env")
            self.assertEqual(r.status_code, 200)
            self.assertIn("DB_PASSWORD=Adm1n-", r.text)
            self.assertEqual(self.upstream_seen(), 0)
            e = self.events()[0]
            self.assertEqual((e["reasons"][0]["detector"], e["risk"], e["action"]), ("honeypot", 0.95, "blocked"))
            self.assertEqual((await gw.get("/products/search?q=laptop")).status_code, 403)   # banned now
        self.assertTrue(self.store.listed("6.6.6.6", "deny"))
        self.assertTrue(self.store.lists()[0]["expires"] > 0)

    async def test_honeypot_in_monitor_mode_never_bans_and_a_ban_expires(self):
        self.cfg["engine"]["mode"] = "monitor"
        async with self.gateway("6.6.6.5") as gw:
            await gw.get("/backup.sql")
            self.assertEqual((await gw.get("/products/search?q=laptop")).status_code, 200)
        self.assertFalse(self.store.listed("6.6.6.5", "deny"))
        self.store.add_list("7.7.7.7", "deny", "t", ttl_s=0.05)
        self.assertTrue(self.store.listed("7.7.7.7", "deny"))
        import time
        time.sleep(0.08)
        self.assertFalse(self.store.listed("7.7.7.7", "deny"))
        self.assertEqual(self.store.lists(), [])

    async def test_canary_from_a_honeypot_is_caught_when_used_later(self):
        async with self.gateway("5.5.5.5") as gw:
            fake = (await gw.get("/api/internal")).json()["api_key"]
        self.cfg["engine"]["mode"] = "monitor"
        async with self.gateway("5.5.5.4") as gw:
            r = await gw.get("/orders", headers={"authorization": f"Bearer {fake}"})
            self.assertEqual(r.status_code, 200)                              # monitor: forwarded
        e = self.events()[0]
        self.assertEqual((e["reasons"][0]["detector"], e["risk"], e["action"]), ("canary_used", 1.0, "would_block"))
        self.assertNotIn(fake, str(e))                                         # the value itself is never logged
        self.cfg["engine"]["mode"] = "block"
        async with self.gateway("5.5.5.3") as gw:
            self.assertEqual((await gw.get("/orders", headers={"authorization": f"Bearer {fake}"})).status_code, 403)

    def upstream_seen(self) -> int:
        return len([e for e in self.events() if e["upstream_status"] == 200 and e["route"] != "honeypot"])


if __name__ == "__main__":
    unittest.main()
