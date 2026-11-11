"""Evaluate Coraza + OWASP CRS on a dataset that was generated THROUGH the proxy
(python -m traffic.generate --url http://127.0.0.1:8080), and compare it with
our own rules detector.

    python -m detection.run_waf [--data data/dataset.csv]
"""
import argparse
import os

import pandas as pd

from detection import metrics
from detection.report import pct, print_report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--rules", default="data/predictions_rules.csv")
    ap.add_argument("--out", default="data/predictions_waf.csv")
    args = ap.parse_args()

    df = pd.read_csv(args.data, keep_default_na=False)
    if (df["waf_block"] == "").any():
        raise SystemExit("This dataset has no Coraza verdicts. Regenerate it through the proxy:\n"
                         "  python -m traffic.generate --url http://127.0.0.1:8080")
    df["waf_flag"] = df["waf_block"].astype(int) == 1
    df["waf_score"] = pd.to_numeric(df["waf_score"])
    df[["id", "waf_score", "waf_rules", "waf_flag"]].to_csv(args.out, index=False)

    print_report(df, "CORAZA + OWASP CRS (paranoia level 1, anomaly threshold 5)",
                 "waf_flag", "waf_score", "waf_rules")

    if not os.path.exists(args.rules):
        return
    df = df.merge(pd.read_csv(args.rules, keep_default_na=False)[["id", "rule_score", "rule_hits", "rule_flag"]], on="id")
    df["rule_flag"] = df["rule_flag"].astype(str) == "True"
    df["rule_score"] = pd.to_numeric(df["rule_score"])
    df["either_flag"] = df["rule_flag"] | df["waf_flag"]

    # How much does the scanner-user-agent rule contribute? Remove its points and re-decide.
    # (Coraza 913100 = critical = 5 points; our SCAN-1 = 3 points.)
    df["waf_noua_flag"] = (df["waf_score"] - 5 * df["waf_rules"].str.contains("913100")) >= 5
    df["rule_noua_flag"] = (df["rule_score"] - 3 * df["rule_hits"].str.contains("SCAN-1")) >= 5

    print("\n" + "=" * 78)
    print("COMPARISON: own rules vs Coraza+CRS vs either one flagging")
    rows = {}
    for name, col in [("own rules", "rule_flag"), ("  own, no user-agent rule", "rule_noua_flag"),
                      ("Coraza+CRS", "waf_flag"), ("  Coraza, no user-agent rule", "waf_noua_flag"),
                      ("either (rules or Coraza)", "either_flag")]:
        m = metrics.overall(df, col)
        rows[name] = {"precision": pct(m["precision"]), "recall": pct(m["recall"]),
                      "F1": pct(m["f1"]), "false alarms": f"{m['fp']} ({pct(m['fpr'])})"}
    print(pd.DataFrame(rows).T.to_string())

    print("\nRecall by attack type:")
    per_type = pd.DataFrame({
        "attacks": metrics.by_attack_type(df, "rule_flag")["attacks"],
        "own rules": metrics.by_attack_type(df, "rule_flag")["recall"].map(pct),
        "Coraza+CRS": metrics.by_attack_type(df, "waf_flag")["recall"].map(pct),
        "Coraza (no UA rule)": metrics.by_attack_type(df, "waf_noua_flag")["recall"].map(pct),
        "either": metrics.by_attack_type(df, "either_flag")["recall"].map(pct),
    })
    print(per_type.to_string())


if __name__ == "__main__":
    main()
