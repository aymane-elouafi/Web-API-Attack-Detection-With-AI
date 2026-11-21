"""Token-class features: the same injection shape gives the same tokens whatever the literal values.   Run:  python -m unittest discover -s tests -t ."""
import unittest

from detection.tokens import tokenize


class TokenTests(unittest.TestCase):
    def test_tautology_variants_share_a_shape(self):
        a, b = tokenize("' OR 1=1 --"), tokenize("x' or 42 = 42 -- ")
        self.assertIn("q K:or n = n c", a)
        self.assertIn("q K:or n = n c", b)

    def test_prose_does_not_look_like_injection(self):
        t = tokenize("his nickname was big al nobody knows why")
        self.assertNotIn("K:", t)
        self.assertNotIn("q", t.split())

    def test_html_js_and_path_tokens(self):
        self.assertIn("T:script", tokenize("<script>alert(1)</script>"))
        self.assertIn("ev", tokenize("<img src=x onerror=alert(1)>").split())
        self.assertIn("S:javascript", tokenize("javascript:alert(1)"))
        self.assertIn("dots", tokenize("../../etc/passwd").split())


if __name__ == "__main__":
    unittest.main()
