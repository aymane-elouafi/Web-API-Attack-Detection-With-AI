"""Incidents, rule-based write-ups and the optional LLM explainer.   Run:  python -m unittest discover -s tests -t ."""
import asyncio
import json
import unittest

import httpx

from wafgw import explainer, incidents


def ev(i, ts, ip="203.0.113.9", path="/products/search", reasons=None, status=200, action="would_block", risk=.95, query="", body=""):
    reasons = reasons or [{"detector": "rules", "score": 10, "strength": 1.0, "detail": "SQLI-1"}]
    return {"id": i, "ts": ts, "client_ip": ip, "method": "GET", "path": path, "query": query, "body_snippet": body, "user_agent": "x",
            "upstream_status": status, "action": action, "risk": risk, "reasons": reasons, "detectors": {r["detector"]: r["strength"] for r in reasons}}


class ClassifyTests(unittest.TestCase):
    def test_rules_schema_behavior_and_ml_signals_map_to_classes(self):
        self.assertEqual(incidents.classify(ev(1, 0)), ["sqli"])
        schema = [{"detector": "schema", "score": 1, "strength": .6, "detail": "privileged_field: 'role' is not a known field of PUT /users/me"}]
        self.assertEqual(incidents.classify(ev(2, 0, reasons=schema)), ["mass_assignment"])
        beh = [{"detector": "behavior", "score": .5, "strength": .5, "detail": {"order_ids": 9, "order_share": .9, "not_found": 4, "failed_logins": 0}}]
        self.assertEqual(incidents.classify(ev(3, 0, reasons=beh)), ["bola"])
        ml = [{"detector": "payload ML", "score": .9, "strength": .9, "detail": ""}]
        self.assertEqual(incidents.classify(ev(4, 0, reasons=ml, query="q=%3Cscript%3Ealert(1)%3C/script%3E")), ["xss"])
        self.assertEqual(incidents.classify(ev(5, 0, reasons=ml, query="q=zzzz")), ["malicious_payload"])
        self.assertEqual(incidents.classify(ev(6, 0, reasons=[{"detector": "behavior", "score": 0, "strength": .1, "detail": {}}])), ["anomaly"])


class BuildTests(unittest.TestCase):
    def test_runs_split_on_client_and_on_quiet_gaps(self):
        evs = [ev(1, 0), ev(2, 10), ev(3, 1000), ev(4, 5, ip="198.51.100.1")]
        self.assertEqual(sorted(len(r) for r in incidents.group(evs, 300)), [1, 1, 2])

    def test_impact_follows_what_the_application_answered(self):
        ok = incidents.build_incident("a", [ev(1, 0, status=200), ev(2, 1, status=404)])
        self.assertEqual(ok["outcome"]["level"], "possibly_succeeded")
        self.assertIn(ok["severity"], ("high", "critical"))
        big = incidents.build_incident("a", [ev(i, i, status=200, path="/orders/%d" % i, reasons=[{"detector": "rules", "score": 10, "strength": 1.0, "detail": "SQLI-1,XSS-1"}]) for i in range(60)])
        self.assertEqual(big["severity"], "critical")                 # many requests, two techniques, worked
        failed = incidents.build_incident("a", [ev(1, 0, status=400), ev(2, 1, status=404)])
        self.assertEqual(failed["outcome"]["level"], "failed")
        stopped = incidents.build_incident("a", [ev(1, 0, status=403, action="blocked")])
        self.assertEqual(stopped["outcome"]["level"], "blocked")
        self.assertLess(incidents.SEVERITIES.index(stopped["severity"]), incidents.SEVERITIES.index(ok["severity"]))

    def test_a_login_that_works_after_many_failures_is_flagged_as_possible_compromise(self):
        auth = [{"detector": "rules", "score": 5, "strength": .5, "detail": "AUTH-1"}]
        flagged = [ev(i, i, path="/login", reasons=auth, status=401, risk=.6) for i in range(1, 9)]
        context = flagged + [ev(99, 10, path="/login", status=200, action="allowed", risk=0)]
        inc = incidents.build_incident("a", flagged, context)
        self.assertEqual(inc["outcome"]["level"], "possibly_succeeded")
        self.assertIn("brute_force", [c["key"] for c in inc["classes"]])

    def test_identical_requests_collapse_into_one_timeline_step(self):
        auth = [{"detector": "rules", "score": 5, "strength": .5, "detail": "AUTH-1"}]
        inc = incidents.build_incident("a", [ev(i, i, path="/login", reasons=auth, status=401, risk=.6) for i in range(1, 31)])
        self.assertEqual(len(inc["timeline"]), 1)
        self.assertEqual(inc["timeline"][0]["count"], 30)

    def test_write_up_has_references_advice_actions_and_no_scratch_keys(self):
        events = [ev(1, 0), ev(2, 1)]
        inc = incidents.build_incident("a", events)
        self.assertIn("CWE-89", inc["refs"]["cwe"])
        self.assertTrue(any("parameterised" in r for r in inc["recommendations"]))
        self.assertEqual(inc["actions"][0]["type"], "ban")
        self.assertTrue(all("_classes" not in e for e in events))
        self.assertEqual(inc["source"], "rules")

    def test_most_severe_incident_comes_first(self):
        scan = [{"detector": "rules", "score": 3, "strength": .3, "detail": "SCAN-1"}]
        out = incidents.build_all([ev(1, 0, ip="1.1.1.1", reasons=scan, risk=.3), ev(2, 0, ip="2.2.2.2")])
        self.assertEqual(out[0]["client_ip"], "2.2.2.2")


class ExplainerTests(unittest.IsolatedAsyncioTestCase):
    def incident(self):
        return incidents.build_incident("203.0.113.77", [ev(1, 0, query="q=SECRET-EVIDENCE", body='{"password":"hunter2"}')])

    def test_facts_leave_out_free_text_and_mask_the_ip(self):
        text = json.dumps(explainer.facts(self.incident()))
        for forbidden in ("SECRET-EVIDENCE", "hunter2", "203.0.113.77"):
            self.assertNotIn(forbidden, text)
        self.assertIn("203.0.113.x", text)

    async def test_disabled_by_default_and_sends_nothing(self):
        calls = []
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json={})))
        with self.assertRaises(PermissionError):
            await explainer.narrate(self.incident(), {}, client)
        self.assertEqual(calls, [])
        self.assertFalse(explainer.status({})["enabled"])

    async def test_openai_and_anthropic_formats_against_a_fake_endpoint(self):
        seen, headers = [], []
        def handler(request):
            headers.append(dict(request.headers))
            seen.append((str(request.url), json.loads(request.content)))
            if request.url.path.endswith("/messages"):
                return httpx.Response(200, json={"content": [{"text": " anthropic words "}]})
            return httpx.Response(200, json={"choices": [{"message": {"content": " openai words "}}]})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        base = {"enabled": True, "url": "http://llm.local:20128", "model": "m"}
        a = await explainer.narrate(self.incident(), base, client)
        b = await explainer.narrate(self.incident(), {**base, "format": "anthropic"}, client)
        self.assertEqual((a["text"], a["source"], b["text"]), ("openai words", "llm", "anthropic words"))
        self.assertTrue(seen[0][0].endswith("/v1/chat/completions") and seen[1][0].endswith("/v1/messages"))
        self.assertNotIn("SECRET-EVIDENCE", json.dumps(seen))
        self.assertNotIn("authorization", headers[0])           # no key configured: no empty Bearer header


if __name__ == "__main__":
    unittest.main()
