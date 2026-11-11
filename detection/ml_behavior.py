"""Unsupervised behavior model (AI model #2): "is this client acting unusually?"

No labels are used. For every request we summarise what the same client did in the last
60 seconds (how many different order ids, how many errors, how many failed logins) and let an Isolation Forest learn what ordinary clients look like. Requests that are
easy to isolate from the crowd get a high anomaly score. This is what can see BOLA (walking
through order ids) and brute force (bursts of failed logins), which have no suspicious text.

Not features: user agent, attack type, variant, label. The client IP is only the grouping key.
"""
import re
from collections import defaultdict, deque

import pandas as pd
from sklearn.ensemble import IsolationForest

WINDOW = 60          # seconds of history per client
ALERT_SHARE = 0.05   # alert budget: flag the 5% most unusual requests
_ORDER = re.compile(r"^/orders/\d+$")
# Only features that describe the two behaviors we hunt (walking order ids, failing logins).
# Adding generic ones (request count, speed, distinct paths) made the ranking clearly worse.
FEATURES = ["order_ids", "order_share", "errors", "error_ratio", "not_found", "failed_logins", "shared_object"]


def behavior_features(df: pd.DataFrame) -> pd.DataFrame:
    """One row per request id, summarising its client's last WINDOW seconds (including itself)."""
    history = defaultdict(deque)
    owners = defaultdict(set)   # order path -> users that requested it so far
    rows = []
    for r in df.sort_values("ts").itertuples(index=False):
        h = history[r.client_ip]
        h.append((r.ts, r.path, r.status))
        while h[0][0] < r.ts - WINDOW:
            h.popleft()
        n = len(h)
        # Did another logged-in user already use this very object? (normal: each order has one user)
        shared = 0
        if _ORDER.match(r.path) and r.user:
            shared = len(owners[r.path] - {r.user})
            owners[r.path].add(r.user)
        orders = [p for _, p, _ in h if _ORDER.match(p)]
        errors = sum(s >= 400 for _, _, s in h)
        rows.append((r.id, len(set(orders)), len(orders) / n, errors, errors / n,
                     sum(s == 404 for _, _, s in h),
                     sum(p == "/login" and s in (401, 403) for _, p, s in h), shared))
    return pd.DataFrame(rows, columns=["id"] + FEATURES).set_index("id")


def anomaly_scores(df: pd.DataFrame) -> pd.Series:
    """Higher = more unusual. Indexed by request id."""
    feats = behavior_features(df)
    forest = IsolationForest(n_estimators=300, random_state=0).fit(feats)
    return pd.Series(-forest.score_samples(feats), index=feats.index)
