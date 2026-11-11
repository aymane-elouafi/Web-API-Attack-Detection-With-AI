"""Supervised payload classifier (AI model #1).

Looks at ONE request at a time -- method, path shape, parameter names and decoded values --
and learns from labeled examples what attacks look like, instead of using hand-written rules.

Kept honest on purpose:
  * It never sees client IP, user agent, attack type or evasion variant (that would be cheating).
  * It is trained only on payload attacks. BOLA and brute force are about behavior, not text,
    so they are left out of training and left to the behavior model.
  * Evaluation groups requests by client IP, so one attacker's requests never sit in both
    the training and the test part.
"""
import json
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, quote

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import MaxAbsScaler

from detection.rules import extract_values
from traffic.payloads import BENIGN_TEXT

TRAIN_ATTACKS = {"sqli", "xss", "path_traversal", "mass_assignment"}
THRESHOLD = 0.5
_SPECIAL = ["'", '"', "<", ">", "%", "..", "--", ";", "(", "="]


def _body_keys(body: str) -> list[str]:
    try:
        obj = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return []
    return sorted(obj) if isinstance(obj, dict) else []


def request_text(method: str, path: str, query: str, body: str) -> tuple[str, str]:
    """(text for the n-gram model, decoded values for the numeric stats)."""
    values = " ".join(extract_values(query, body))
    names = [k for k, _ in parse_qsl(query, keep_blank_values=True)] + _body_keys(body)
    parts = [method, re.sub(r"/\d+", "/{id}", path)] + [f"key:{n}" for n in names] + [values]
    return " ".join(parts).lower(), values.lower()


def _stats(values: str) -> list[float]:
    """Length, randomness (entropy), share of odd characters, counts of attack-ish characters."""
    n = len(values) or 1
    entropy = -sum(c / n * math.log2(c / n) for c in Counter(values).values())
    odd = sum(not ch.isalnum() and ch != " " for ch in values) / n
    return [math.log1p(len(values)), entropy, odd] + [math.log1p(values.count(t)) for t in _SPECIAL]


def prepare(df: pd.DataFrame) -> tuple[list[str], np.ndarray]:
    pairs = [request_text(r.method, r.path, r.query, r.body) for r in df.itertuples(index=False)]
    return [t for t, _ in pairs], np.array([_stats(v) for _, v in pairs])


def benign_extras() -> tuple[list[str], np.ndarray]:
    """Extra harmless training rows (same request shapes as the real traffic)."""
    rows = [("GET", "/products/search", "q=" + quote(t, safe=""), "") for t in BENIGN_TEXT]
    rows += [("POST", "/comments", "", json.dumps({"text": t})) for t in BENIGN_TEXT]
    return prepare(pd.DataFrame(rows, columns=["method", "path", "query", "body"]))


class PayloadModel:
    def fit(self, texts, nums, y):
        self.tfidf = TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2, sublinear_tf=True)
        self.scale = MaxAbsScaler()
        X = hstack([self.tfidf.fit_transform(texts), csr_matrix(self.scale.fit_transform(nums))]).tocsr()
        self.clf = LogisticRegression(C=10, max_iter=2000, class_weight="balanced").fit(X, y)
        return self

    def score(self, texts, nums) -> np.ndarray:
        X = hstack([self.tfidf.transform(texts), csr_matrix(self.scale.transform(nums))]).tocsr()
        return self.clf.predict_proba(X)[:, 1]


def out_of_fold_scores(df: pd.DataFrame, folds: int = 5) -> np.ndarray:
    """Attack probability for every request, from a model that never saw that client's traffic."""
    texts, nums = prepare(df)
    texts = np.array(texts, dtype=object)
    y = df.label.to_numpy()
    trainable = df.attack_type.isin(TRAIN_ATTACKS | {"normal"}).to_numpy()
    extra_texts, extra_nums = benign_extras()
    scores = np.zeros(len(df))
    for train, test in GroupKFold(folds).split(df, y, groups=df.client_ip):
        train = train[trainable[train]]
        model = PayloadModel().fit(list(texts[train]) + extra_texts, np.vstack([nums[train], extra_nums]),
                                   np.concatenate([y[train], np.zeros(len(extra_texts), dtype=int)]))
        scores[test] = model.score(list(texts[test]), nums[test])
    return scores


def fit_full(df: pd.DataFrame) -> PayloadModel:
    """Final model: every trainable request in df plus the harmless extras."""
    df = df[df.attack_type.isin(TRAIN_ATTACKS | {"normal"})]
    texts, nums = prepare(df)
    e_texts, e_nums = benign_extras()
    return PayloadModel().fit(texts + e_texts, np.vstack([nums, e_nums]),
                              np.concatenate([df.label.to_numpy(), np.zeros(len(e_texts), dtype=int)]))
