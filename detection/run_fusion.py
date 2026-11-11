"""Final evaluation: rules-only vs Coraza-only vs AI-only vs hybrid (fused), plus the novel-payload test.

Needs the prediction files from run_rules, run_waf, run_ml and run_behavior.

    python -m detection.run_fusion [--data data/dataset.csv] [--waf-url http://127.0.0.1:8080]

--waf-url (optional) sends the ~45 novel-payload requests through the Coraza proxy so Coraza
joins the novel-payload comparison.
"""
import argparse
import json

import httpx
import pandas as pd

from detection import metrics
from detection.fusion import THRESHOLD, fuse, strengths
from detection.ml_payload import THRESHOLD as ML_THRESHOLD, fit_full, prepare
from detection.report import pct
from detection.rules import THRESHOLD as RULE_THRESHOLD, stateless_hits
from detection.run_novel import requests as novel_requests

PREDICTIONS = {"rules": ("data/predictions_rules.csv", ["rule_score", "rule_flag"]),
               "waf": ("data/predictions_waf.csv", ["waf_score", "waf_flag"]),
               "ml": ("data/predictions_ml.csv", ["ml_prob", "ml_flag"]),
               "behavior": ("data/predictions_behavior.csv", ["beh_prob", "beh_flag"])}


def load(data: str = "data/dataset.csv") -> pd.DataFrame:
    """The dataset joined with every detector's prediction columns."""
    df = pd.read_csv(data, keep_default_na=False).drop(columns=["waf_score"])
    for path, cols in PREDICTIONS.values():
        p = pd.read_csv(path, keep_default_na=False)[["id"] + cols]
        for c in cols:
            p[c] = p[c].astype(str).eq("True") if c.endswith("_flag") else pd.to_numeric(p[c])
        df = df.merge(p, on="id")
    return df


def table(df: pd.DataFrame, flags: dict[str, str]) -> None:
    rows = {}
    for name, col in flags.items():
        m = metrics.overall(df, col)
        rows[name] = {"precision": pct(m["precision"]), "recall": pct(m["recall"]), "F1": pct(m["f1"]),
                      "false alarms": f"{m['fp']} ({pct(m['fpr'])})"}
    print(pd.DataFrame(rows).T.to_string())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--waf-url", default="")
    args = ap.parse_args()

    df = load(args.data)

    s = strengths(df)
    groups = {"hybrid (all four, fused)": ["rules", "coraza", "payload ML", "behavior"],
              "AI only (payload + behavior)": ["payload ML", "behavior"]}
    flags = {"rules only": "rule_flag", "Coraza only": "waf_flag", "AI payload only": "ml_flag",
             "AI behavior only": "beh_flag"}
    for name, cols in groups.items():
        df[name] = fuse(s[cols]) >= THRESHOLD
        flags[name] = name
    df["any single detector"] = df[["rule_flag", "waf_flag", "ml_flag", "beh_flag"]].any(axis=1)
    flags["union of flags (no fusion)"] = "any single detector"

    print(f"FINAL EVALUATION  {len(df)} requests, {int(df.label.sum())} attacks "
          f"(fused risk >= {THRESHOLD}: noisy-OR of per-detector alert strengths)\n")
    table(df, flags)
    print("\nRecall by attack type:")
    print(pd.DataFrame({"attacks": metrics.by_attack_type(df, "rule_flag")["attacks"]} |
                       {n: metrics.by_attack_type(df, c)["recall"].map(pct) for n, c in flags.items()}).to_string())
    hy = "hybrid (all four, fused)"
    missed = df[(df.label == 1) & ~df[hy]]
    print(f"\nHybrid misses {len(missed)} of {int(df.label.sum())} attacks: "
          + ", ".join(f"{k} {v}" for k, v in missed.attack_type.value_counts().items()))
    for kind, g in missed.groupby("attack_type"):
        for r in g.head(2).itertuples():
            print(f"  [{kind}] {r.method} {r.path}?{r.query} {r.body}"[:150])
    fps = df[(df.label == 0) & df[hy]]
    print(f"Hybrid false alarms: {len(fps)}")
    for r in fps.head(5).itertuples():
        print(f"  {r.method} {r.path}?{r.query} {r.body}"[:150])

    novel(args)


def novel(args) -> None:
    train = pd.read_csv(args.data, keep_default_na=False)
    model = fit_full(train)

    t = novel_requests()
    t["ml_prob"] = model.score(*prepare(t))
    t["ml_flag"] = t.ml_prob >= ML_THRESHOLD
    t["rule_score"] = [sum(v for _, v in stateless_hits(r.query, r.body)) for r in t.itertuples()]
    t["rule_flag"] = t.rule_score >= RULE_THRESHOLD
    flags = {"own rules": "rule_flag", "AI payload": "ml_flag"}
    cols = ["rules", "payload ML"]
    if args.waf_url:
        with httpx.Client(base_url=args.waf_url, timeout=15) as http:
            heads = [http.request(r.method, r.path + ("?" + r.query if r.query else ""),
                                  json=json.loads(r.body) if r.body else None,
                                  headers={"Host": "shop.example.test", "User-Agent": "Mozilla/5.0"}).headers
                     for r in t.itertuples()]
        t["waf_score"] = [float(h.get("x-waf-score", 0)) for h in heads]
        t["waf_flag"] = [h.get("x-waf-block") == "1" for h in heads]
        flags["Coraza+CRS"] = "waf_flag"
        cols.insert(1, "coraza")
    t["hybrid (fused)"] = fuse(strengths(t)[cols]) >= THRESHOLD
    flags["hybrid (fused)"] = "hybrid (fused)"

    print("\n" + "=" * 78 + f"\nNOVEL-PAYLOAD TEST  {int(t.label.sum())} unseen attacks, {int((t.label == 0).sum())} harmless look-alikes"
          + ("" if args.waf_url else "   (Coraza skipped: pass --waf-url)") + "\n(single requests only: the behavior model needs a client's history)\n")
    rows = {}
    for name, col in flags.items():
        a, b = t[t.label == 1], t[t.label == 0]
        rows[name] = {"attacks caught": f"{int(a[col].sum())}/{len(a)} ({pct(a[col].mean())})",
                      "false alarms": f"{int(b[col].sum())}/{len(b)}"}
    print(pd.DataFrame(rows).T.to_string())
    print("\nCaught by attack type:")
    print(pd.DataFrame({n: t[t.label == 1].groupby("attack_type")[c].apply(lambda x: f"{int(x.sum())}/{len(x)}")
                        for n, c in flags.items()}).to_string())


if __name__ == "__main__":
    main()
