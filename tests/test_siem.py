import json
import socket
import tempfile
import unittest

from wafgw.siem import Siem, cef

EV = {"ts": 1700000000.5, "request_id": "abc", "client_ip": "203.0.113.7", "method": "GET", "host": "shop", "path": "/a|b",
      "user_agent": "curl", "action": "blocked", "risk": 0.93,
      "reasons": json.dumps([{"detector": "rules", "strength": 1.0, "detail": "SQLI-1 x=1\nnext"}])}


class SiemTest(unittest.TestCase):
    def test_cef_escapes_header_pipes_and_extension_equals_and_newlines(self):
        line = cef(EV)
        self.assertTrue(line.startswith("CEF:0|wafgw|web-api-waf|1.0|rules|blocked GET /a\\|b|9|"))
        self.assertIn("src=203.0.113.7", line)
        self.assertIn("msg=SQLI-1 x\\=1\\nnext", line)
        self.assertNotIn("\n", line)

    def test_file_and_syslog_get_flagged_events_only(self):
        d = tempfile.mkdtemp()
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(2)
        s = Siem({"file": d + "/e.jsonl", "syslog": f"127.0.0.1:{rx.getsockname()[1]}", "only_flagged": True})
        s.emit({**EV, "action": "allowed"})
        s.emit(EV)
        self.assertEqual(json.loads(open(d + "/e.jsonl").read())["request_id"], "abc")
        self.assertTrue(rx.recv(70000).decode().startswith("<14>wafgw: CEF:0|"))


if __name__ == "__main__":
    unittest.main()
