"""Unit tests for the external-data helpers (no downloads needed).   Run:  python -m unittest discover -s tests -t ."""
import unittest

import pandas as pd

from detection.external_data import _DIRTY, carry, classify, dedupe, key


def frame(rows):
    return pd.DataFrame([dict(method="GET", path=p, query=q, body="", label=l, attack_type="x", source="s", group="g")
                         for p, q, l in rows])


class ExternalDataTests(unittest.TestCase):
    def test_dedupe_ignores_case_encoding_and_whitespace(self):
        df = frame([("/a", "q=a%20b", 0), ("/A", "q=A  B", 0), ("/a", "q=a%2520b", 0), ("/a", "q=c", 0)])
        self.assertEqual(len(dedupe(df)), 2)

    def test_dedupe_drops_keys_with_conflicting_labels_and_purged_keys(self):
        df = frame([("/a", "q=1", 0), ("/a", "q=1", 1), ("/b", "q=2", 1), ("/c", "q=3", 0)])
        out = dedupe(df, drop=key(frame([("/c", "q=3", 0)])))
        self.assertEqual(list(out.path), ["/b"])

    def test_same_text_gets_the_same_carrier_whatever_its_class(self):
        self.assertEqual(carry("' or 1=1 --"), carry("' or 1=1 --"))
        self.assertEqual({carry(f"text {i}")[1] for i in range(30)}, {"/search", "/files", "/comments"})

    def test_classify_and_dirty_filter(self):
        self.assertEqual(classify("q=%27%20union%20select%201--"), "sqli")
        self.assertEqual(classify("<script>alert(1)</script>"), "xss")
        self.assertEqual(classify("../../etc/passwd"), "path_traversal")
        self.assertEqual(classify("hello world"), "other")
        self.assertTrue(_DIRTY.search("/x.php?u=http://evil/a.txt"))
        self.assertFalse(_DIRTY.search("/manual/en/faq/index.html"))


if __name__ == "__main__":
    unittest.main()
