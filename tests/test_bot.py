"""Tests for the bot / scanner detector.   Run:  python -m unittest discover -s tests -t ."""
import unittest

from wafgw.bot import BotDetector

BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
BROWSER_HEADERS = [(b"accept", b"text/html"), (b"accept-language", b"en"), (b"cookie", b"s=1")]


def req(ts=0.0, path="/p", ua=BROWSER, ip="10.0.0.1", headers=None, **kw):
    return {"ts": ts, "client_ip": ip, "path": path, "user_agent": ua, "session": "", "headers": headers, **kw}


def feed(bot, n, gap, path=lambda i: "/p", status=200, **kw):
    last = (0.0, "", None)
    for i in range(n):
        last = bot.inspect(req(i * gap, path(i), **kw))
        last[2][2] = status
    return last


class SignatureTests(unittest.TestCase):
    def test_scanner_user_agent_alerts_alone(self):
        s, detail, _ = BotDetector().inspect(req(ua="sqlmap/1.7.2#stable (https://sqlmap.org)"))
        self.assertGreaterEqual(s, 0.5)
        self.assertIn("sqlmap", detail)

    def test_scripting_client_is_only_weak_evidence(self):
        s, detail, _ = BotDetector().inspect(req(ua="curl/8.5.0"))
        self.assertTrue(0 < s < 0.3, s)
        self.assertIn("automation client", detail)

    def test_real_browser_with_normal_headers_is_clean(self):
        self.assertEqual(BotDetector().inspect(req(headers=BROWSER_HEADERS))[0], 0.0)

    def test_fake_browser_without_browser_headers_is_weakly_flagged(self):
        s, detail, _ = BotDetector().inspect(req(headers=[(b"accept", b"*/*")]))
        self.assertTrue(0 < s < 0.3)
        self.assertIn("accept-language", detail)

    def test_headers_are_skipped_when_the_proxy_does_not_pass_them(self):
        self.assertEqual(BotDetector().inspect(req(headers=None))[0], 0.0)

    def test_http10_and_missing_user_agent(self):
        s, detail, _ = BotDetector().inspect(req(ua="", http_version="1.0", headers=BROWSER_HEADERS))
        self.assertIn("no user agent", detail)
        self.assertIn("old protocol", detail)


class RhythmTests(unittest.TestCase):
    def test_machine_regular_timing_is_flagged(self):
        s, detail, _ = feed(BotDetector(), 12, 1.0)
        self.assertGreater(s, 0.3)
        self.assertIn("machine timing", detail)

    def test_irregular_human_timing_is_not(self):
        bot, t = BotDetector(), 0.0
        for g in [3, 11, 5, 19, 2, 8, 14, 4, 9, 6, 17, 3]:
            t += g
            s, _, e = bot.inspect(req(t))
            e[2] = 200
        self.assertEqual(s, 0.0)

    def test_burst_rate(self):
        s, detail, _ = feed(BotDetector(), 20, 0.05)
        self.assertGreaterEqual(s, 0.5)
        self.assertIn("burst", detail)

    def test_walking_missing_urls_alerts(self):
        s, detail, _ = feed(BotDetector(), 12, 4.0, path=lambda i: f"/x{i}", status=404)
        self.assertGreaterEqual(s, 0.5)
        self.assertIn("URL walking", detail)

    def test_sustained_refusals_are_credential_guessing(self):
        s, detail, _ = feed(BotDetector(), 12, 4.0, path=lambda i: "/login", status=401)
        self.assertGreaterEqual(s, 0.5)
        self.assertIn("credential guessing", detail)

    def test_clients_are_tracked_separately(self):
        bot = BotDetector()
        feed(bot, 12, 0.05, ip="10.0.0.9")
        self.assertEqual(bot.inspect(req(ip="10.0.0.2", ts=5))[0], 0.0)

    def test_old_requests_fall_out_of_the_window(self):
        bot = BotDetector()
        feed(bot, 12, 0.05)
        self.assertEqual(bot.inspect(req(ts=500.0))[0], 0.0)


if __name__ == "__main__":
    unittest.main()
