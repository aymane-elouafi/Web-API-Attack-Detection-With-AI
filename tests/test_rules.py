"""Unit tests for the rules detector.   Run:  python -m unittest discover -s tests -t ."""
import json
import unittest
from urllib.parse import quote

from detection.rules import THRESHOLD, StatefulRules, stateless_hits


def score(query="", body="", ua="") -> int:
    return sum(sev for _, sev in stateless_hits(query, body, ua))


def q(text: str) -> str:
    return "q=" + quote(text, safe="")


class SignatureTests(unittest.TestCase):
    def test_sql_injection_is_flagged(self):
        for payload in ["' OR '1'='1", "' OR 1=1 --", "admin' --",
                        "' UNION SELECT id, username, password FROM users --",
                        "1' AND SLEEP(5) --", "'; DROP TABLE users; --"]:
            self.assertGreaterEqual(score(q(payload)), THRESHOLD, payload)

    def test_sql_injection_with_case_and_comment_tricks_is_flagged(self):
        self.assertGreaterEqual(score(q("'/**/oR/**/1=1/**/--")), THRESHOLD)
        self.assertGreaterEqual(score(q("' uNiOn SeLeCt 1,2,3 --")), THRESHOLD)

    def test_xss_is_flagged(self):
        for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                        "<svg/onload=alert(1)>", "<a href=\"javascript:alert(1)\">x</a>"]:
            self.assertGreaterEqual(score(body=json.dumps({"text": payload})), THRESHOLD, payload)

    def test_path_traversal_is_flagged(self):
        for raw in ["../../etc/passwd", "..%2f..%2fetc%2fpasswd", "/etc/passwd",
                    "%2e%2e/%2e%2e/etc/passwd", "..%5c..%5cetc%5cpasswd"]:
            self.assertGreaterEqual(score("name=" + raw), THRESHOLD, raw)

    def test_double_encoding_is_only_suspicious(self):
        s = score("q=" + quote(quote("' OR '1'='1", safe=""), safe=""))
        self.assertTrue(0 < s < THRESHOLD, s)

    def test_double_encoding_plus_trailing_comment_adds_up(self):
        # "-" is never URL-encoded, so a trailing "--" survives double encoding and
        # its 3 points add to the 3 for "multiple encoding": 6 >= THRESHOLD.
        s = score("q=" + quote(quote("' OR 1=1 --", safe=""), safe=""))
        self.assertGreaterEqual(s, THRESHOLD)

    def test_harmless_lookalikes_are_not_flagged(self):
        for text in ["men's laptop", "laptop & accessories", "laptop 50% off", "usb-c laptop"]:
            self.assertEqual(score(q(text)), 0, text)
        for text in ["I love it <3", "Is 5 > 3 stars fair? Maybe 4.", "Q&A: does it support USB-C?",
                     "Price went from $120 to $99 -- nice deal",
                     "Can someone explain the difference, select the right model or the union of both features?",
                     "Would I buy it again? OR maybe wait for the next version."]:
            self.assertEqual(score(body=json.dumps({"text": text})), 0, text)
        self.assertEqual(score(body=json.dumps({"username": "user15", "password": "Passw0rd15!"})), 0)


class StatefulTests(unittest.TestCase):
    def test_failed_logins_trigger_auth_rule(self):
        st = StatefulRules()
        hits = [st.check(i * 2.0, "1.2.3.4", "/login", 401) for i in range(6)]
        self.assertEqual([bool(h) for h in hits], [False, False, False, False, True, True])

    def test_single_typo_does_not_trigger(self):
        st = StatefulRules()
        self.assertEqual(st.check(0, "1.2.3.4", "/login", 401), [])
        self.assertEqual(st.check(5, "1.2.3.4", "/login", 200), [])

    def test_request_burst_triggers_rate_rule(self):
        st = StatefulRules()
        hits = [st.check(i * 0.2, "1.2.3.4", "/orders/1", 200) for i in range(30)]
        self.assertFalse(any(hits[:20]))
        self.assertTrue(hits[25])

    def test_clients_are_tracked_separately(self):
        st = StatefulRules()
        for i in range(4):
            st.check(i, "1.1.1.1", "/login", 401)
        self.assertEqual(st.check(5, "2.2.2.2", "/login", 401), [])


if __name__ == "__main__":
    unittest.main()
