"""Evaluate the supervised payload classifier and compare it with the rules and Coraza.

    python -m detection.run_ml [--data data/dataset.csv]
"""
import argparse
import os

import pandas as pd

from detection import metrics
from detection.ml_payload import THRESHOLD, out_of_fold_scores
from detection.report import pct, print_report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--out", default="data/predictions_ml.csv")
    args = ap.parse_args()

    df = pd.read_csv(args.data, keep_default_na=False)
    df["ml_prob"] = out_of_fold_scores(df)
    df["ml_flag"] = df.ml_prob >= THRESHOLD
    df["ml_score"] = df.ml_prob.where(df.ml_prob >= 0.2, 0).round(3)   # "suspicious" starts at 0.2
    df["ml_hits"] = ""
    df[["id", "ml_prob", "ml_flag"]].to_csv(args.out, index=False)

    print_report(df, f"PAYLOAD CLASSIFIER (char n-grams + logistic regression, flag when p >= {THRESHOLD})",
                 "ml_flag", "ml_score", "ml_hits")

    flags = {"own rules": ("data/predictions_rules.csv", "rule_flag"),
             "Coraza+CRS": ("data/predictions_waf.csv", "waf_flag")}
    cols = {"payload ML": "ml_flag"}
    for name, (path, col) in flags.items():
        if os.path.exists(path):
            df = df.merge(pd.read_csv(path, keep_default_na=False)[["id", col]], on="id")
            df[col] = df[col].astype(str) == "True"
            cols[name] = col
    if len(cols) > 1:
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
        per_type = pd.DataFrame({"attacks": metrics.by_attack_type(df, "ml_flag")["attacks"]} |
                                {n: metrics.by_attack_type(df, c)["recall"].map(pct) for n, c in cols.items()})
        print(per_type.to_string())
    print(f"\nPredictions saved to {args.out}")


if __name__ == "__main__":
    main()
