"""Run the rules-based detector on the dataset and print an evaluation report.

    python -m detection.run_rules [--data data/dataset.csv] [--threshold 5]
"""
import argparse

import pandas as pd

from detection.report import print_report
from detection.rules import THRESHOLD, detect


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--out", default="data/predictions_rules.csv")
    ap.add_argument("--threshold", type=int, default=THRESHOLD)
    args = ap.parse_args()

    df = pd.read_csv(args.data, keep_default_na=False)
    pred = detect(df, args.threshold)
    pred.to_csv(args.out, index=False)
    df = df.merge(pred, on="id")

    print_report(df, f"RULES-ONLY DETECTOR (own rules, flag when score >= {args.threshold})",
                 "rule_flag", "rule_score", "rule_hits")
    print(f"\nPredictions saved to {args.out}")


if __name__ == "__main__":
    main()
