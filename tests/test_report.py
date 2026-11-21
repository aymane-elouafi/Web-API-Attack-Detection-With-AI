"""Reports and the admin routes for incidents / reports.   Run:  python -m unittest discover -s tests -t ."""
import json
import tempfile
import time
import unittest
from pathlib import Path

import httpx

from wafgw import config, report
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.store import Store

HOOK = {"slack": "text", "discord": "content"}


def log(store, i, ts, ip="203.0.113.9", path="/products/search", action="would_block", status=200, risk=.95, detail="SQLI-1", query="q=%27"):
    reasons = [{"detector": "rules", "score": 10, "strength": 1.0, "detail": detail}]
    store.log({"ts": ts, "request_id": f"r{i}", "client_ip": ip, "method": "GET", "host": "h", "path": path, "query": query, "user_agent": "u",
               "body_snippet": "", "upstream_status": status, "action": action, "risk": risk, "detectors": json.dumps({"rules": 1.0}),
               "reasons": json.dumps(reasons), "latency_ms": 1.0, "route": "", "response_flags": "[]", "resp_bytes": 0})


class ReportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = config.load("/nonexistent.toml")
        self.cfg["store"]["path"] = f"{self.tmp.name}/waf.db"
        self.cfg["reports"].update(dir=f"{self.tmp.name}/reports", webhook=True)
        self.store = Store(self.cfg["store"]["path"])
        self.now = time.time()
        for i in range(6):
            log(self.store, i, self.now - 100 + i)
        log(self.store, 10, self.now - 50, ip="198.51.100.5", path="/<script>alert(1)</script>", action="blocked", status=403, query="")
        log(self.store, 11, self.now - 40, ip="198.51.100.6", path="/ok", action="allowed", risk=0.0, detail="")
        self.store.flush()
        self.store.set_feedback(self.store.events(limit=1)[0]["id"], "benign")
        self.engine = Engine(self.cfg, self.store)

    async def asyncTearDown(self):
        self.tmp.cleanup()

    def build(self):
        return report.build_report(self.store, self.now - 3600, self.now + 1, {"mode": "monitor", "threshold": .5, "models": {"payload": False}})

    def test_numbers_incidents_and_recommendations(self):
        r = self.build()
        s = r["summary"]
        self.assertEqual((s["requests"], s["flagged"], s["blocked"], s["would_block"]), (8, 7, 1, 6))
        self.assertEqual(s["incidents"], 2)
        self.assertEqual(r["attack_types"][0]["key"], "sqli")
        self.assertEqual(r["false_positives"]["marked_benign"], 1)
        self.assertTrue(any("monitor" in x["text"] for x in r["recommendations"]))
        self.assertTrue(any("payload detector is not loaded" in x["text"] for x in r["recommendations"]))
        self.assertEqual(r["detectors"]["labels"], ["rules"])

    def test_html_is_self_contained_and_escapes_request_text(self):
        page = report.render_html(self.build())
        self.assertNotIn("<script", page)
        self.assertIn("&lt;script&gt;", page)                      # the attack path is shown, harmlessly
        for external in ("http://", "https://", "src=", "@import"):
            self.assertNotIn(external, page)
        self.assertIn("@media print", page)

    async def test_files_listing_and_webhook_delivery(self):
        r = self.build()
        path = report.write_files(r, self.cfg["reports"]["dir"])
        self.assertTrue(Path(path).is_file() and Path(path.replace(".html", ".json")).is_file())
        self.assertEqual([f["name"] for f in report.list_files(self.cfg["reports"]["dir"])], [Path(path).name])
        self.store.put("alerts", {"url": "https://hooks.example/x", "kind": "slack"})
        got = []
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: got.append(json.loads(req.content)) or httpx.Response(200)))
        self.assertEqual(await report.deliver(self.store, r, path, client), "HTTP 200")
        self.assertIn("2 incident(s)", got[0]["text"])
        self.store.put("alerts", {})
        self.assertEqual(await report.deliver(self.store, r, path), "no webhook configured")

    async def test_admin_routes(self):
        app = build_admin(self.engine, self.store, "tok", self.cfg)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://a", headers={"authorization": "Bearer tok"}) as a:
            lst = (await a.get(f"/api/incidents?since={self.now - 3600}")).json()["incidents"]
            self.assertEqual(len(lst), 2)
            self.assertNotIn("timeline", lst[0])
            one = (await a.get(f"/api/incidents/{lst[0]['id']}")).json()
            self.assertTrue(one["timeline"] and one["narrative"] and one["actions"])
            self.assertEqual((await a.get("/api/incidents/999999")).status_code, 404)
            denied = await a.post(f"/api/incidents/{lst[0]['id']}/narrative")
            self.assertEqual(denied.status_code, 403)                # LLM off by default: nothing is sent
            self.assertFalse((await a.get("/api/explainer")).json()["enabled"])
            made = (await a.post("/api/reports")).json()
            self.assertTrue(Path(made["path"]).is_file())
            name = Path(made["path"]).name
            self.assertIn("text/html", (await a.get(f"/api/reports/{name}")).headers["content-type"])
            self.assertEqual((await a.get("/api/reports/..%2Fwaf.db")).status_code, 404)
            self.assertEqual((await a.get("/api/reports/x.txt")).status_code, 400)
            self.assertEqual((await a.get(f"/api/report?since={self.now - 3600}")).json()["summary"]["requests"], 8)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://a") as anon:
            self.assertEqual((await anon.get("/api/incidents")).status_code, 401)


if __name__ == "__main__":
    unittest.main()
