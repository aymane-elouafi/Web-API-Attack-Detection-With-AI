"""Evaluation helpers shared by every detector (rules now, AI later).

A detector adds a boolean "flag" column to the dataset; these functions compare
it with the ground-truth `label` column.

  precision = of the requests we flagged, how many were real attacks
  recall    = of the real attacks, how many we caught
  FPR       = of the normal requests, how many we wrongly flagged
"""
import pandas as pd


def overall(df: pd.DataFrame, flag: str) -> dict:
    y, p = df["label"] == 1, df[flag].astype(bool)
    tp, fp = int((y & p).sum()), int((~y & p).sum())
    fn, tn = int((y & ~p).sum()), int((~y & ~p).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fp / (fp + tn) if fp + tn else 0.0}


def by_attack_type(df: pd.DataFrame, flag: str) -> pd.DataFrame:
    attacks = df[df["label"] == 1]
    g = attacks.groupby("attack_type")[flag]
    out = pd.DataFrame({"attacks": g.size(), "caught": g.sum().astype(int)})
    out["recall"] = out["caught"] / out["attacks"]
    return out


def by_variant(df: pd.DataFrame, flag: str) -> pd.DataFrame:
    attacks = df[df["label"] == 1]
    g = attacks.groupby(["attack_type", "variant"])[flag]
    out = pd.DataFrame({"attacks": g.size(), "caught": g.sum().astype(int)})
    out["recall"] = out["caught"] / out["attacks"]
    return out
