"""Tests for the threat-intel module.   Run:  python -m unittest discover -s tests -t ."""
import tempfile
import threading
import time
import unittest
from pathlib import Path

from wafgw.intel import Intel, parse_list, parse_networks

BLOCK = "# comment\n192.0.2.0/24 ; SBL1 test net\n198.51.100.23\nnot-an-ip\n2001:db8::/32\n"
NETS = "cidr,country,asn,org\n203.0.113.0/24,XX,64502,Example Telecom\n"


class ParsingTests(unittest.TestCase):
    def test_spamhaus_style_lines_notes_and_bad_lines(self):
        rows, bad = parse_list(BLOCK)
        self.assertEqual([str(n) for n, _ in rows], ["192.0.2.0/24", "198.51.100.23/32", "2001:db8::/32"])
        self.assertEqual(rows[0][1], "SBL1 test net")
        self.assertEqual(bad, 1)

    def test_networks_csv_with_header(self):
        rows, bad = parse_networks(NETS)
        self.assertEqual((len(rows), bad), (1, 0))
        self.assertEqual(rows[0][1], {"country": "XX", "asn": 64502, "org": "Example Telecom"})


class IntelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "x.block.txt").write_text(BLOCK)
        (self.dir / "ok.allow.txt").write_text("192.0.2.77\n")
        (self.dir / "networks.csv").write_text(NETS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_blocklist_hit_alerts_with_a_reason(self):
        s, why = Intel(str(self.dir)).check("192.0.2.9")
        self.assertGreaterEqual(s, 0.5)
        self.assertIn("x.block.txt", why)
        self.assertIn("SBL1", why)

    def test_ipv6_and_unknown_and_garbage(self):
        i = Intel(str(self.dir))
        self.assertGreater(i.check("2001:db8::5")[0], 0)
        self.assertEqual(i.check("8.8.8.8"), (0.0, ""))
        self.assertEqual(i.check("not an ip"), (0.0, ""))

    def test_allowlist_wins_lookup(self):
        self.assertIsNotNone(Intel(str(self.dir)).allowed("192.0.2.77"))
        self.assertIsNone(Intel(str(self.dir)).allowed("192.0.2.78"))

    def test_country_and_asn_rules_come_from_the_networks_file(self):
        self.assertEqual(Intel(str(self.dir)).check("203.0.113.5")[0], 0.0)           # known network, no rule
        s, why = Intel(str(self.dir), country_deny=["xx"]).check("203.0.113.5")
        self.assertGreaterEqual(s, 0.5)
        self.assertIn("country XX", why)
        self.assertIn("AS64502", Intel(str(self.dir), asn_deny=[64502]).check("203.0.113.5")[1])

    def test_files_reload_when_they_change(self):
        i = Intel(str(self.dir))
        self.assertEqual(i.check("8.8.4.4")[0], 0.0)
        time.sleep(0.01)
        (self.dir / "y.block.txt").write_text("8.8.4.0/24\n")
        self.assertTrue(i.reload_if_changed())
        self.assertGreater(i.check("8.8.4.4")[0], 0)
        self.assertFalse(i.reload_if_changed())

    def test_import_export_delete_roundtrip_and_validation(self):
        i = Intel(str(self.dir))
        self.assertEqual(i.save("blocklist", "feed1", "10.9.0.0/16\n")["entries"], 1)
        self.assertGreater(i.check("10.9.1.1")[0], 0)
        self.assertEqual(i.export("blocklist", "feed1"), "10.9.0.0/16\n")
        self.assertTrue(i.delete("blocklist", "feed1"))
        self.assertEqual(i.check("10.9.1.1")[0], 0.0)
        for bad in [("blocklist", "../evil", "1.1.1.1\n"), ("blocklist", "ok", "junk only\n"), ("nope", "a", "1.1.1.1\n")]:
            with self.assertRaises(ValueError):
                i.save(*bad)
        self.assertFalse(i.delete("blocklist", "../../etc/passwd"))

    def test_dnsbl_runs_in_the_background_and_is_cached(self):
        asked, gate = [], threading.Event()
        def resolver(host):
            gate.wait(2)                                                                 # a slow DNS server
            asked.append(host)
            return host.endswith("5.113.0.203.bl.example")
        i = Intel(str(self.dir), dnsbl_zones=["bl.example"], dnsbl_enabled=True, resolver=resolver)
        self.assertEqual(i.check("203.0.113.5")[0], 0.0)                                # the request does not wait for DNS
        gate.set()
        i._pending["203.0.113.5"].result(timeout=2)
        s, why = i.check("203.0.113.5")
        self.assertGreater(s, 0.5)
        self.assertIn("bl.example", why)
        n = len(asked)
        i.check("203.0.113.5")
        self.assertEqual(len(asked), n)                                                  # served from the cache


if __name__ == "__main__":
    unittest.main()
