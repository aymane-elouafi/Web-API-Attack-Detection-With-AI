"""Score fusion: turn every detector's output into one 0-1 risk score.

Each detector is converted to an "alert strength" where 0.5 means "this detector alone would
raise an alert" (rules / Coraza: score 5 of 10, payload ML: p = 0.5, behavior: its alert-budget
cutoff). Strengths are combined with a noisy-OR, 1 - prod(1 - s): one confident detector is
enough, and several half-convinced ones add up. A request is flagged at risk >= 0.5.
The threshold and the mappings are a stated policy, not tuned on the labels.
"""
import pandas as pd

THRESHOLD = 0.5


def strengths(df: pd.DataFrame) -> pd.DataFrame:
    """df may hold: rule_score, waf_score, ml_prob, beh_prob + beh_flag. Missing detectors are skipped."""
    s = pd.DataFrame(index=df.index)
    if "rule_score" in df:
        s["rules"] = (df.rule_score / 10).clip(0, 1)
    if "waf_score" in df:
        s["coraza"] = (df.waf_score / 10).clip(0, 1)
    if "ml_prob" in df:
        s["payload ML"] = df.ml_prob
    if "beh_prob" in df:
        p = df.beh_prob.rank(pct=True)
        cutoff = p[df.beh_flag].min()                       # percentile where the behavior model alerts
        s["behavior"] = (0.5 * (p / cutoff) ** 4).clip(0, 1)  # only the unusual tail contributes
    return s


def fuse(parts: pd.DataFrame) -> pd.Series:
    """Noisy-OR of the chosen strength columns."""
    return 1 - (1 - parts).prod(axis=1)
