"""Smoke test for the dashboard API (needs the data/ prediction files).   Run:  python -m unittest discover -s tests -t ."""
import unittest

from fastapi.testclient import TestClient

from dashboard.app import app

client = TestClient(app)


class DashboardTests(unittest.TestCase):
    def test_summary_has_hybrid_and_threshold_moves_alerts(self):
        s = client.get("/api/eval/summary?threshold=0.5").json()
        self.assertEqual(s["detectors"][-1]["name"], "hybrid")
        loose = client.get("/api/eval/alerts?threshold=0.2&show=flagged").json()["total"]
        strict = client.get("/api/eval/alerts?threshold=0.8&show=flagged").json()["total"]
        self.assertGreater(loose, strict)

    def test_missed_list_contains_only_attacks(self):
        rows = client.get("/api/eval/alerts?show=missed&limit=50").json()["rows"]
        self.assertTrue(rows and all(r["truth"] != "normal" for r in rows))

    def test_clients_are_ranked_and_timeline_matches(self):
        rows = client.get("/api/eval/clients").json()["rows"]
        risks = [r["max_risk"] for r in rows]
        self.assertEqual(risks, sorted(risks, reverse=True))
        t = client.get("/api/eval/client", params={"ip": rows[0]["client"]}).json()["rows"]
        self.assertEqual(len(t), rows[0]["requests"])

    def test_feed_replays_in_time_order_and_ends(self):
        a = client.get("/api/eval/feed?after=-1&n=5").json()
        b = client.get(f"/api/eval/feed?after={a['next']}&n=5").json()
        ts = [r["ts"] for r in a["rows"] + b["rows"]]
        self.assertEqual(ts, sorted(ts))
        self.assertTrue(client.get("/api/eval/feed?after=999999").json()["done"])


if __name__ == "__main__":
    unittest.main()
