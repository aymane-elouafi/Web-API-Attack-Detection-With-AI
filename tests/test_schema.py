"""Unit tests for the API schema detector.   Run:  python -m unittest discover -s tests -t ."""
import json
import tempfile
import unittest
from pathlib import Path

from detection.schema import SchemaModel, template
from wafgw import config
from wafgw.engine import Engine

SHOP = [("GET", f"/orders/{i}", "", "") for i in range(1, 30)]
SHOP += [("PUT", "/users/me", "", json.dumps({"email": f"u{i}@x.io", "name": f"Name{i}"})) for i in range(30)]
SHOP += [("GET", "/search", f"q=word{i}&sort={'asc' if i % 2 else 'desc'}&page={i % 9}", "") for i in range(40)]
SHOP += [("POST", "/login", "", json.dumps({"username": f"user{i}", "password": "pw"})) for i in range(30)]


def kinds(model, *req):
    return {f["kind"] for f in model.score(*req)}


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.m = SchemaModel().learn(SHOP)

    def test_template_masks_ids_but_keeps_trailing_slash(self):
        self.assertEqual(template("/orders/17/items/3f2a9c1e5b7d4a60"), "/orders/{id}/items/{id}")
        self.assertNotEqual(template("/a/b"), template("/a/b/"))

    def test_normal_requests_have_no_findings(self):
        self.assertEqual(self.m.score("GET", "/orders/99"), [])
        self.assertEqual(self.m.score("GET", "/search", "q=hello&sort=asc&page=3"), [])
        self.assertEqual(self.m.score("PUT", "/users/me", "", '{"email": "z@x.io", "name": "Zed"}'), [])

    def test_structural_findings(self):
        self.assertEqual(kinds(self.m, "GET", "/admin"), {"unknown_endpoint"})
        self.assertEqual(kinds(self.m, "DELETE", "/orders/3"), {"method_not_allowed"})
        self.assertIn("unknown_param", kinds(self.m, "GET", "/search", "q=a&sort=asc&page=1&debug=1"))
        self.assertIn("missing_required", kinds(self.m, "GET", "/search", "q=a&sort=asc"))
        self.assertIn("type_mismatch", kinds(self.m, "GET", "/search", "q=a&sort=asc&page=abc"))
        self.assertIn("enum_violation", kinds(self.m, "GET", "/search", "q=a&sort=sideways&page=1"))

    def test_privileged_field_is_a_strong_finding(self):
        f = self.m.score("PUT", "/users/me", "", '{"email": "a@x.io", "name": "A", "role": "admin"}')
        self.assertEqual([x["kind"] for x in f], ["privileged_field"])
        self.assertGreaterEqual(self.m.strength(f), 0.5)

    def test_strength_is_noisy_or_and_soft_findings_need_company(self):
        self.assertAlmostEqual(self.m.strength([{"strength": 0.3}, {"strength": 0.3}]), 0.51)
        self.assertLess(self.m.strength(self.m.score("GET", "/search", "q=" + "w" * 40 + "&sort=asc&page=1")), 0.5)   # one soft finding (long value) warns only

    def test_rare_traffic_is_not_learned(self):
        poisoned = SchemaModel().learn(SHOP + [("GET", "/search", "q=x&sort=asc&page=1&evil=1", "")] * 3 + [("GET", "/backdoor", "", "")] * 2)
        self.assertIn("unknown_param", kinds(poisoned, "GET", "/search", "q=x&sort=asc&page=1&evil=1"))
        self.assertEqual(kinds(poisoned, "GET", "/backdoor"), {"unknown_endpoint"})

    def test_json_round_trip_keeps_behaviour(self):
        again = SchemaModel.from_json(self.m.to_json())
        req = ("GET", "/search", "q=a&sort=asc&page=1&debug=1")
        self.assertEqual(again.score(*req), self.m.score(*req))

    def test_openapi_needs_no_traffic(self):
        spec = {"paths": {"/orders/{order_id}": {"get": {"parameters": [{"name": "expand", "in": "query", "schema": {"type": "boolean"}}]}},
                          "/users/me": {"put": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/U"}}}}}}},
                "components": {"schemas": {"U": {"properties": {"email": {"type": "string"}}, "required": ["email"]}}}}
        m = SchemaModel.from_openapi(spec)
        self.assertEqual(m.score("GET", "/orders/5", "expand=true"), [])
        self.assertIn("type_mismatch", kinds(m, "GET", "/orders/5", "expand=maybe!"))
        self.assertEqual(kinds(m, "PUT", "/users/me", "", '{"email": "a@b.co", "role": "admin"}'), {"privileged_field"})
        self.assertIn("missing_required", kinds(m, "PUT", "/users/me", "", "{}"))


class EngineIntegrationTests(unittest.TestCase):
    def test_gateway_engine_flags_schema_breaks_and_skips_without_a_model(self):
        info = dict(method="PUT", path="/users/me", query="", body='{"email": "a@x.io", "name": "A", "role": "admin"}',
                    user_agent="", client_ip="1.1.1.1", session="", ts=1.0)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config.load("/nonexistent.toml")
            cfg["models"]["dir"] = tmp
            self.assertEqual(Engine(cfg).inspect(dict(info)).action, "allow")          # no schema.json: detector skipped
            Path(tmp, "schema.json").write_text(SchemaModel().learn(SHOP).to_json())
            v = Engine(cfg).inspect(dict(info))
            self.assertGreaterEqual(v.risk, 0.5)
            self.assertIn("schema", v.detectors)
            self.assertIn("privileged_field", next(r for r in v.reasons if r["detector"] == "schema")["detail"])
            cfg["routes"] = [{"prefix": "/users", "mode": "monitor", "schema": False}]
            self.assertEqual(Engine(cfg).inspect(dict(info)).action, "allow")          # per-route switch


if __name__ == "__main__":
    unittest.main()
