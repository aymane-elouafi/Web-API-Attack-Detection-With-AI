"""Console tests: real gateway admin API + store + engine (temp DB), console app on top.   Run:  python -m unittest discover -s tests -t ."""
import os
import tempfile
import time
import unittest
from unittest import mock

import httpx
from fastapi.testclient import TestClient

from dashboard import console
from dashboard.app import app
from wafgw import config
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.store import Store

SQLI_Q = "q=%27%20OR%201%3D1%20--"


def event(i, path="/products/search", query=SQLI_Q, action="would_block", risk=0.9, detectors=None, ip="1.1.1.1"):
    return {"ts": time.time() - 10 + i / 100, "request_id": f"r{i}", "client_ip": ip, "method": "GET", "host": "h", "path": path,
            "query": query, "user_agent": "ua", "body_snippet": "", "upstream_status": 200, "action": action, "risk": risk,
            "detectors": __import__("json").dumps(detectors or {"rules": 1.0}), "latency_ms": 1.0, "route": "",
            "reasons": __import__("json").dumps([{"detector": "rules", "score": 10, "strength": 1.0, "detail": "SQLI-1"}])}


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cfg = config.load("/nonexistent.toml")
        cfg["store"]["path"] = f"{self.tmp.name}/waf.db"
        self.store = Store(cfg["store"]["path"])
        self.engine = Engine(cfg, self.store)
        patcher = mock.patch.dict(os.environ, {"WAF_ADMIN_TOKEN": "t0ken"})
        patcher.start()
        self.addCleanup(patcher.stop)
        admin = build_admin(self.engine, self.store, "t0ken")
        console.set_gateway_client(httpx.AsyncClient(transport=httpx.ASGITransport(admin), base_url="http://gw"))
        self.addCleanup(console.set_gateway_client, None)
        self.client = TestClient(app)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, *events):
        for e in events:
            self.store.log(e)
        self.store.flush()

    def test_explain_shows_evidence_and_threshold(self):
        self.put(event(1))
        x = self.client.get("/api/explain/1").json()
        self.assertEqual(x["threshold"], 0.5)
        self.assertTrue(any(t["source"] == "rules" and t["rule"] == "SQLI-1" and t["text"] for t in x["terms"]))
        self.assertIn("1=1", x["decoded"]["query"])

    def test_api_security_and_reload_calls_reach_the_gateway(self):
        self.assertIn("endpoints", self.client.get("/api/gw/schema").json())       # the API Security page
        self.assertIn("reloaded", self.client.post("/api/gw/reload").json())
        self.assertEqual(self.client.get("/api/gw/not-a-call").status_code, 404)

    def test_feedback_and_audit_are_recorded(self):
        self.put(event(1))
        self.client.post("/api/gw/feedback", json={"event_id": 1, "verdict": "benign"})
        self.assertEqual(self.client.get("/api/explain/1").json()["event"]["feedback"]["verdict"], "benign")
        audit = self.client.get("/api/gw/audit").json()["audit"]
        self.assertEqual(audit[0]["actor"], "console")

    def test_simulation_blocks_an_exemption_that_would_lose_known_attacks(self):
        self.put(event(1), event(2, ip="2.2.2.2"))
        both = [{"prefix": "/products/search", "param": "", "detector": d} for d in ("rules", "payload ML")]
        sim = self.client.post("/api/simulate", json={"exemptions": both}).json()
        self.assertFalse(sim["safe"])
        self.assertEqual(sim["stored"]["newly_allowed"], 2)
        r = self.client.post("/api/apply", json={"exemptions": both})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.store.exemptions(), [])

    def test_attack_marked_by_the_user_cannot_be_exempted(self):
        self.put(event(1, query="q=laptop", detectors={"payload ML": 0.6}, risk=0.6))
        self.client.post("/api/gw/feedback", json={"event_id": 1, "verdict": "attack"})
        ex = [{"prefix": "/products/search", "param": "", "detector": "payload ML"}]
        sim = self.client.post("/api/simulate", json={"exemptions": ex}).json()
        self.assertEqual(sim["stored"]["known_attacks_lost"], [1])
        self.assertFalse(sim["safe"])

    def test_safe_exemption_applies_and_the_engine_silences_that_detector(self):
        self.put(*[event(i, path="/search", query="q=a+--+b", detectors={"payload ML": 0.6}, risk=0.6, ip=f"9.9.9.{i}") for i in range(1, 5)])
        for i in range(1, 5):
            self.client.post("/api/gw/feedback", json={"event_id": i, "verdict": "benign"})
        items = self.client.get("/api/inbox").json()["items"]
        self.assertEqual(items[0]["suggestion"]["prefix"], "/search")
        self.assertTrue(items[0]["safe"])
        self.assertEqual(self.client.post("/api/apply", json={"exemptions": [items[0]["suggestion"]]}).status_code, 200)
        v = self.engine.inspect({"method": "GET", "path": "/search", "query": "q=a+--+b", "body": "", "user_agent": "u",
                                 "client_ip": "5.5.5.5", "session": "", "ts": time.time()})
        self.assertTrue(all(r["strength"] == 0 for r in v.reasons if r["detector"] == "payload ML"))

    def test_policy_import_is_all_or_nothing(self):
        bad = {"version": 1, "mode": "block", "lists": [{"ip": "not-an-ip", "kind": "deny"}]}
        self.assertEqual(self.client.post("/api/gw/policy", json=bad).status_code, 400)
        self.assertEqual(self.engine.mode, "monitor")
        good = {"version": 1, "mode": "block", "threshold": 0.6, "lists": [{"ip": "10.0.0.0/8", "kind": "deny", "note": "x"}],
                "exemptions": [{"prefix": "/a", "detector": "rules"}], "routes": [{"prefix": "/admin", "mode": "block"}]}
        out = self.client.post("/api/gw/policy", json=good).json()
        self.assertEqual((out["mode"], out["threshold"], len(out["lists"]), len(out["exemptions"])), ("block", 0.6, 1, 1))

    def test_login_wall(self):
        with mock.patch.dict(os.environ, {"CONSOLE_PASSWORD": "hunter2"}):
            self.assertEqual(self.client.get("/api/overview").status_code, 401)
            self.assertEqual(self.client.post("/api/login", json={"password": "nope"}).status_code, 401)
            self.assertEqual(self.client.post("/api/login", json={"password": "hunter2"}).status_code, 200)
            self.assertEqual(self.client.get("/api/overview").status_code, 200)

    def test_token_never_reaches_the_browser(self):
        self.assertNotIn("t0ken", self.client.get("/").text + self.client.get("/static/app.js").text + self.client.get("/api/session").text)


if __name__ == "__main__":
    unittest.main()
