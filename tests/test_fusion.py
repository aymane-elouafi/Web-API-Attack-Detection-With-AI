"""Unit tests for score fusion.   Run:  python -m unittest discover -s tests -t ."""
import unittest

import pandas as pd

from detection.fusion import THRESHOLD, fuse, strengths


class FusionTests(unittest.TestCase):
    def test_one_detector_at_its_alert_level_flags_and_weak_ones_add_up(self):
        df = pd.DataFrame({"rule_score": [5, 0, 3], "waf_score": [0, 0, 3], "ml_prob": [0.0, 0.1, 0.3]})
        risk = fuse(strengths(df))
        self.assertGreaterEqual(risk[0], THRESHOLD)        # rules alone at 5
        self.assertLess(risk[1], THRESHOLD)                # nothing convincing
        self.assertGreaterEqual(risk[2], THRESHOLD)        # three half-signals together


if __name__ == "__main__":
    unittest.main()
