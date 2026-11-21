"""Worker processes share one database: a ban made by one must be visible to the others after refresh_lists()."""
import tempfile
import unittest

from wafgw.store import Store


class SharedBansTest(unittest.TestCase):
    def test_other_process_sees_ban_after_refresh(self):
        path = tempfile.mkdtemp() + "/w.db"
        a, b = Store(path), Store(path)
        a.add_list("203.0.113.9", "deny", "honeypot")
        self.assertFalse(b.listed("203.0.113.9", "deny"))      # b has not looked yet
        b.refresh_lists()
        self.assertTrue(b.listed("203.0.113.9", "deny"))
        a.remove_list("203.0.113.9")
        b.refresh_lists()
        self.assertFalse(b.listed("203.0.113.9", "deny"))


if __name__ == "__main__":
    unittest.main()
