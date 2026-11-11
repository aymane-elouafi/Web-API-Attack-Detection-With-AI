"""Unit tests for the payload classifier's features.   Run:  python -m unittest discover -s tests -t ."""
import unittest

import pandas as pd

from detection.ml_payload import prepare, request_text


class FeatureTests(unittest.TestCase):
    def test_features_ignore_everything_but_the_request_itself(self):
        a = pd.DataFrame([dict(method="GET", path="/orders/7", query="x=1", body="", client_ip="1.1.1.1",
                               user_agent="sqlmap/1.7", attack_type="bola", variant="none", label=1)])
        b = a.assign(client_ip="9.9.9.9", user_agent="Mozilla/5.0", attack_type="normal", variant="case", label=0)
        (ta, na), (tb, nb) = prepare(a), prepare(b)
        self.assertEqual(ta, tb)
        self.assertTrue((na == nb).all())

    def test_ids_are_masked_and_field_names_kept(self):
        self.assertIn("/orders/{id}", request_text("GET", "/orders/17", "", "")[0])
        self.assertIn("key:role", request_text("PUT", "/users/me", "", '{"role": "admin"}')[0])


if __name__ == "__main__":
    unittest.main()
