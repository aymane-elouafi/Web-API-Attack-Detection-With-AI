"""Engine / proxy / admin integration of the bot, adaptive-rate-limit and intel features.   Run:  python -m unittest discover -s tests -t ."""
import tempfile
import unittest
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from wafgw import config
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.proxy import build_app
from wafgw.store import Store

BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def info(ip="10.0.0.1", ts=1000.0, path="/products/search", ua=BROWSER):
    return {"method": "GET", "path": path, "query": "q=lamp", "body": "", "user_agent": ua, "client_ip": ip, "session": "", "ts": ts}


class EngineFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.intel_dir = Path(self.tmp.name) / "intel"
        self.intel_dir.mkdir()
        self.cfg = config.load("/nonexistent.toml")
        self.cfg["store"]["path"] = f"{self.tmp.name}/waf.db"
        self.cfg["models"]["dir"] = self.tmp.name                  # no models: only rules, bot and intel run
        self.cfg["intel"]["dir"] = str(self.intel_dir)
        self.cfg["engine"]["mode"] = "block"
        self.cfg["routes"] = []

    def tearDown(self):
        self.tmp.cleanup()

    def engine(self):
        return Engine(self.cfg, Store(self.cfg["store"]["path"]))

    def test_blocklisted_client_is_flagged_and_blocked_with_a_reason(self):
        (self.intel_dir / "t.block.txt").write_text("192.0.2.0/24 ; test\n")
        v = self.engine().inspect(info(ip="192.0.2.9"))
        self.assertEqual(v.action, "block")
        self.assertIn("t.block.txt", next(r["detail"] for r in v.reasons if r["detector"] == "intel"))

    def test_allowlisted_client_skips_inspection(self):
        (self.intel_dir / "t.allow.txt").write_text("192.0.2.77\n")
        (self.intel_dir / "t.block.txt").write_text("192.0.2.0/24\n")
        v = self.engine().inspect(info(ip="192.0.2.77", ua="sqlmap/1.7"))
        self.assertEqual(v.action, "allow")

    def test_scanner_user_agent_alone_reaches_the_alert_level(self):
        v = self.engine().inspect(info(ua="Nikto/2.5.0"))
        self.assertGreaterEqual(v.risk, 0.5)
        self.assertIn("bot", v.detectors)

    def test_clean_browser_request_has_no_bot_or_intel_reason(self):
        v = self.engine().inspect(info())
        self.assertEqual(v.action, "allow")
        self.assertFalse({"bot", "intel"} & set(v.detectors))

    def test_adaptive_rate_limit_tightens_for_risky_clients(self):
        self.cfg["rate_limit"].update(enabled=True, rate_per_s=0.001, burst=10)
        calm, risky = self.engine(), self.engine()
        risky.risk_ewma["10.0.0.1"] = 0.9
        allowed = lambda e: sum(e._bucket_ok("10.0.0.1", 1000.0) for _ in range(10))
        self.assertEqual(allowed(calm), 10)
        self.assertLess(allowed(risky), 4)

    def test_route_can_override_the_rate_limit(self):
        self.cfg["rate_limit"].update(enabled=True, rate_per_s=0.001, burst=10, adaptive=False)
        e = self.engine()
        self.assertEqual(sum(e._bucket_ok("10.0.0.2", 1000.0, {"burst": 3}) for _ in range(10)), 3)


class ProxyAndAdminTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cfg = config.load("/nonexistent.toml")
        cfg["store"]["path"] = f"{self.tmp.name}/waf.db"
        cfg["models"]["dir"] = self.tmp.name
        cfg["intel"]["dir"] = f"{self.tmp.name}/intel"
        cfg["proxy"]["upstream"] = "http://upstream"
        self.upstream = httpx.AsyncClient(transport=httpx.ASGITransport(Starlette(routes=[
            Route("/{p:path}", lambda r: JSONResponse({"ok": True}))])), base_url="http://upstream")
        self.store = Store(cfg["store"]["path"])
        self.engine = Engine(cfg, self.store)
        self.gw = httpx.AsyncClient(transport=httpx.ASGITransport(build_app(cfg, self.engine, self.store, client=self.upstream),
                                                                  client=("10.0.0.5", 1)), base_url="http://gw")
        self.admin = httpx.AsyncClient(transport=httpx.ASGITransport(build_admin(self.engine, self.store, "tok")), base_url="http://admin",
                                       headers={"authorization": "Bearer tok"})

    async def asyncTearDown(self):
        await self.upstream.aclose()
        self.tmp.cleanup()

    async def test_proxy_passes_headers_so_a_fake_browser_is_noticed(self):
        await self.gw.get("/p", headers={"user-agent": BROWSER, "accept": "*/*"})
        self.store.flush()
        reasons = self.store.events()[0]["reasons"]
        self.assertIn("accept-language", next(r["detail"] for r in reasons if r["detector"] == "bot"))

    async def test_admin_import_lookup_policy_and_bots_endpoints(self):
        r = await self.admin.post("/api/intel/import", json={"kind": "blocklist", "name": "feed", "text": "10.0.0.0/24 ; lab\n"})
        self.assertEqual(r.json()["entries"], 1)
        look = (await self.admin.get("/api/intel/lookup", params={"ip": "10.0.0.5"})).json()
        self.assertGreater(look["strength"], 0.5)
        await self.gw.get("/p")                                                         # now flagged by the blocklist
        self.store.flush()
        self.assertEqual((await self.admin.get("/api/intel")).json()["hits_24h"], 1)
        self.assertEqual((await self.admin.post("/api/intel/import", json={"kind": "blocklist", "name": "../x", "text": "1.1.1.1"})).status_code, 400)
        self.assertEqual((await self.admin.post("/api/intel/policy", json={"country_deny": ["kp"], "asn_deny": ["AS64500"]})).json(),
                         {"country_deny": ["KP"], "asn_deny": [64500]})
        self.assertEqual((await self.admin.get("/api/intel/export", params={"kind": "blocklist", "name": "feed"})).text, "10.0.0.0/24 ; lab\n")
        self.assertEqual((await self.admin.delete("/api/intel/blocklist/feed")).status_code, 200)
        self.assertEqual((await self.admin.get("/api/bots")).status_code, 200)


if __name__ == "__main__":
    unittest.main()
