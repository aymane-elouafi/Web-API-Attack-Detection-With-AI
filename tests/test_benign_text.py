"""Hard-negative generator and blind harmless set.   Run:  python -m unittest discover -s tests -t ."""
import re
import unittest

from detection.benign_text import generate
from detection.harmless_set import HARMLESS

MARKERS = r"<\s*script|\.\./|union\s+(all\s+)?select|\bon\w+\s*=|javascript:"
ATTACK_MARKERS = re.compile(MARKERS + r"|['\"]\s*or\s+['\"\d]", re.I)
SET_MARKERS = re.compile(MARKERS, re.I)   # the hand-written set may hold '"affect" or "effect"' on purpose: a hard negative


class BenignTextTests(unittest.TestCase):
    def test_generator_is_deterministic_unique_and_big_enough(self):
        a = generate(2000, seed=3)
        self.assertEqual(a, generate(2000, seed=3))
        self.assertEqual(len({t for t, _ in a}), 2000)
        self.assertGreater(len({i for _, i in a}), 20)               # many template families

    def test_no_text_is_an_attack(self):
        for text in [t for t, _ in generate(3000)]:
            self.assertIsNone(ATTACK_MARKERS.search(text), text)
        for text in HARMLESS:
            self.assertIsNone(SET_MARKERS.search(text), text)

    def test_blind_set_is_200_distinct_sentences(self):
        self.assertEqual(len(set(HARMLESS)), 200)


if __name__ == "__main__":
    unittest.main()
