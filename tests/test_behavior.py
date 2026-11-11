"""Unit tests for the behavior features.   Run:  python -m unittest discover -s tests -t ."""
import unittest

import pandas as pd

from detection.ml_behavior import WINDOW, behavior_features


def reqs(rows, users=None):
    users = users or [""] * len(rows)
    return pd.DataFrame([dict(id=i, ts=t, client_ip=ip, path=p, status=s, user=u)
                         for i, ((t, ip, p, s), u) in enumerate(zip(rows, users))])


class BehaviorFeatureTests(unittest.TestCase):
    def test_failed_logins_and_order_ids_are_counted_per_client(self):
        f = behavior_features(reqs([(0, "a", "/login", 401), (1, "a", "/login", 401), (2, "b", "/login", 401),
                                    (3, "a", "/orders/5", 404), (4, "a", "/orders/6", 404)]))
        self.assertEqual(f.loc[1, "failed_logins"], 2)       # client b's failure is not counted for a
        self.assertEqual(f.loc[4, "order_ids"], 2)
        self.assertEqual(f.loc[4, "not_found"], 2)

    def test_order_used_by_another_user_is_flagged_as_shared(self):
        f = behavior_features(reqs([(0, "a", "/orders/5", 200), (1, "b", "/orders/5", 200), (2, "a", "/orders/5", 200)],
                                   users=["alice", "bob", "alice"]))
        self.assertEqual(list(f.shared_object), [0, 1, 1])

    def test_old_requests_fall_out_of_the_window(self):
        f = behavior_features(reqs([(0, "a", "/login", 401), (WINDOW + 1, "a", "/login", 401)]))
        self.assertEqual(f.loc[1, "failed_logins"], 1)


if __name__ == "__main__":
    unittest.main()
