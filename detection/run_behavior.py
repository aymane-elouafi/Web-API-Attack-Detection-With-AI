"""Evaluate the unsupervised behavior model and compare it with every other detector.

    python -m detection.run_behavior [--data data/dataset.csv]
"""
import argparse
import os

import pandas as pd

from detection import metrics
from detection.ml_behavior import ALERT_SHARE, anomaly_scores
from detection.report import pct, print_report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--out", default="data/predictions_behavior.csv")
    args = ap.parse_args()

    df = pd.read_csv(args.data, keep_default_na=False)
    df["beh_prob"] = df.id.map(anomaly_scores(df))
    cutoff = df.beh_prob.quantile(1 - ALERT_SHARE)
    df["beh_flag"] = df.beh_prob >= cutoff
    df["beh_score"] = df.beh_prob.where(df.beh_flag, 0).round(3)
    df["beh_hits"] = ""
    df[["id", "beh_prob", "beh_flag"]].to_csv(args.out, index=False)

    print_report(df, f"BEHAVIOR MODEL (Isolation Forest, no labels; flag top {ALERT_SHARE:.0%} most unusual)",
                 "beh_flag", "beh_score", "beh_hits")

    cols = {"behavior ML": "beh_flag"}
    for name, path, col in [("payload ML", "data/predictions_ml.csv", "ml_flag"),
                            ("own rules", "data/predictions_rules.csv", "rule_flag"),
                            ("Coraza+CRS", "data/predictions_waf.csv", "waf_flag")]:
        if os.path.exists(path):
            df = df.merge(pd.read_csv(path, keep_default_na=False)[["id", col]], on="id")
            df[col] = df[col].astype(str) == "True"
            cols[name] = col
    df["any_flag"] = df[list(cols.values())].any(axis=1)
    cols["any of them"] = "any_flag"
    print("\n" + "=" * 78 + "\nCOMPARISON (same requests, same labels)")
    rows = {}
    for name, col in cols.items():
        m = metrics.overall(df, col)
        rows[name] = {"precision": pct(m["precision"]), "recall": pct(m["recall"]),
                      "false alarms": f"{m['fp']} ({pct(m['fpr'])})"}
    print(pd.DataFrame(rows).T.to_string())
    print("\nRecall by attack type:")
    print(pd.DataFrame({"attacks": metrics.by_attack_type(df, "beh_flag")["attacks"]} |
                       {n: metrics.by_attack_type(df, c)["recall"].map(pct) for n, c in cols.items()}).to_string())
    print(f"\nPredictions saved to {args.out}")


if __name__ == "__main__":
    main()
