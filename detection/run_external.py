"""Train the payload classifier on real data and evaluate it honestly.

    python -m detection.run_external [--skip-cv]

Training: project synthetic data + harmless sentences + FWAF + payload corpora + OWASP CRS tests.
Held out ENTIRELY: CSIC 2010 (purged from training). Reports: cross-dataset result on CSIC (before/after),
leave-family-out cross-validation inside the training data, rules baseline, punctuation-heavy benign text,
novel hand-written attacks, and a format-only baseline that shows how much a model could score
by file-format shortcuts alone.
"""
import argparse

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

from detection.external_data import load_all
from detection.ml_payload import THRESHOLD, PayloadModel, prepare
from detection.report import pct
from detection.rules import THRESHOLD as RULE_THRESHOLD, stateless_hits
from detection.run_novel import requests as novel_requests


def fit(df: pd.DataFrame) -> PayloadModel:
    texts, nums = prepare(df)
    return PayloadModel().fit(texts, nums, df.label.to_numpy())


def summary(df: pd.DataFrame, prob: np.ndarray) -> dict:
    y, flag = df.label.to_numpy(), prob >= THRESHOLD
    tp, fp = int((flag & (y == 1)).sum()), int((flag & (y == 0)).sum())
    fn, tn = int((~flag & (y == 1)).sum()), int((~flag & (y == 0)).sum())
    return {"AUC": round(roc_auc_score(y, prob), 3), "precision": pct(tp / max(tp + fp, 1)), "recall": pct(tp / max(tp + fn, 1)),
            "false-alarm rate": pct(fp / max(fp + tn, 1))}


def by_class(df: pd.DataFrame, flag: np.ndarray) -> pd.Series:
    a = df[df.label == 1].assign(flag=flag[df.label.to_numpy() == 1])
    return a.groupby("attack_type").flag.mean().map(pct)


def rules_flags(df: pd.DataFrame) -> np.ndarray:
    return np.array([sum(s for _, s in stateless_hits(r.query, r.body)) >= RULE_THRESHOLD for r in df.itertuples()])


def format_features(df: pd.DataFrame) -> np.ndarray:
    """Only the SHAPE of a request: lengths, slashes, character-class shares. No attack knowledge."""
    rows = []
    for r in df.itertuples():
        s = r.path + r.query + r.body
        n = len(s) or 1
        rows.append([len(r.path), len(r.query), len(r.body), r.path.count("/"), int(bool(r.query)), int(r.method == "POST"),
                     sum(c.isdigit() for c in s) / n, sum(c.isalpha() for c in s) / n, sum(c == "%" for c in s) / n,
                     sum(not c.isalnum() and c not in "/%" for c in s) / n])
    return np.array(rows)


def novel_eval(models: dict) -> pd.DataFrame:
    n = novel_requests()
    benign = n[n.attack_type == "normal"]
    atk = n[n.label == 1]
    rows = {}
    for name, m in models.items():
        t, x = prepare(n)
        p = m.score(t, x) >= THRESHOLD
        rows[name] = {"novel attacks caught": f"{int(p[n.label == 1].sum())}/{len(atk)}",
                      "look-alike false alarms": f"{int(p[n.label == 0].sum())}/{len(benign)}"}
    flags = np.array([sum(s for _, s in stateless_hits(r.query, r.body)) >= RULE_THRESHOLD for r in n.itertuples()])
    rows["own rules"] = {"novel attacks caught": f"{int(flags[n.label == 1].sum())}/{len(atk)}",
                         "look-alike false alarms": f"{int(flags[n.label == 0].sum())}/{len(benign)}"}
    return pd.DataFrame(rows).T


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-cv", action="store_true", help="skip the slow leave-family-out cross-validation")
    args = ap.parse_args()

    train, csic = load_all()
    print(f"training set {len(train)} rows ({int(train.label.sum())} attacks, {int((train.label == 0).sum())} benign); "
          f"held-out CSIC 2010 {len(csic)} rows ({int(csic.label.sum())} attacks, {int((csic.label == 0).sum())} normal)")
    print(train.groupby(["source", "label"]).size().rename("rows").to_string())
    c_texts, c_nums = prepare(csic)

    # 1) ablation + before/after on the held-out dataset
    steps = {"before: synthetic + harmless text (old model)": ["synthetic", "benign_text"],
             "+ FWAF": ["synthetic", "benign_text", "benign_gen", "fwaf_good", "fwaf_bad"],
             "+ payload lists + CRS tests": ["synthetic", "benign_text", "benign_gen", "payload_lists", "crs_tests"],
             "after: everything": sorted(train.source.unique())}
    models, rows, classes = {}, {}, {}
    for name, sources in steps.items():
        models[name] = m = fit(train[train.source.isin(sources)])
        p = m.score(c_texts, c_nums)
        rows[name] = summary(csic, p)
        classes[name] = by_class(csic, p >= THRESHOLD)
    flags = rules_flags(csic)
    rows["own rules (no training)"] = {"AUC": "-", "precision": pct(flags[csic.label == 1].sum() / max(flags.sum(), 1)),
                                       "recall": pct(flags[csic.label == 1].mean()), "false-alarm rate": pct(flags[csic.label == 0].mean())}
    classes["own rules (no training)"] = by_class(csic, flags)
    print("\n=== CROSS-DATASET: CSIC 2010 (never seen in training) ===")
    print(pd.DataFrame(rows).T.to_string())
    print("\nrecall by attack class on CSIC (classes are regex guesses from the text; 'other' = no pattern matched):")
    print(pd.DataFrame(classes).T.to_string())

    # 2) punctuation-heavy benign text + novel attacks
    print("\n=== NOVEL HAND-WRITTEN ATTACKS / HARMLESS LOOK-ALIKES (run_novel lists) ===")
    print(novel_eval({"before": models[next(iter(steps))], "after": models["after: everything"]}).to_string())

    # 3) format-only baseline: how much can request shape alone explain?
    f_train, f_csic = format_features(train), format_features(csic)
    shape = HistGradientBoostingClassifier(random_state=0)
    groups = (train.source + ":" + train.group).to_numpy()
    oof = np.zeros(len(train))
    for tr, te in GroupKFold(5).split(f_train, train.label, groups):
        oof[te] = HistGradientBoostingClassifier(random_state=0).fit(f_train[tr], train.label.iloc[tr]).predict_proba(f_train[te])[:, 1]
    shape.fit(f_train, train.label)
    print("\n=== LEAKAGE CHECK: model that sees only the SHAPE of requests (lengths, slashes, character shares) ===")
    print(f"AUC inside the training data (leave-family-out): {roc_auc_score(train.label, oof):.3f}")
    for s in ("fwaf_bad", "fwaf_good", "payload_lists", "crs_tests", "benign_gen", "synthetic"):
        m = (train.source == s).to_numpy()
        print(f"   {s:14s} flagged by shape-only model: {pct((oof[m] >= 0.5).mean())}  (true label share attack: {pct(train.label[m].mean())})")
    print(f"AUC on held-out CSIC 2010:                       {roc_auc_score(csic.label, shape.predict_proba(f_csic)[:, 1]):.3f}")

    # 4) leave-family-out cross-validation of the real model inside the training data
    if not args.skip_cv:
        oof = np.zeros(len(train))
        t, x = prepare(train)
        t = np.array(t, dtype=object)
        for tr, te in GroupKFold(5).split(train, train.label, groups):
            oof[te] = PayloadModel().fit(list(t[tr]), x[tr], train.label.iloc[tr].to_numpy()).score(list(t[te]), x[te])
        print("\n=== LEAVE-FAMILY-OUT CROSS-VALIDATION inside the training data (5 folds, grouped by source file / path stem) ===")
        print(pd.Series(summary(train, oof)).to_string())
        print("recall by attack class:\n" + by_class(train, oof >= THRESHOLD).to_string())
        print("false-alarm rate per benign source:")
        for s in ("fwaf_good", "benign_gen", "benign_text", "crs_tests", "synthetic"):
            m = ((train.source == s) & (train.label == 0)).to_numpy()
            print(f"   {s:14s} {pct((oof[m] >= THRESHOLD).mean())}  ({int(m.sum())} rows)")


if __name__ == "__main__":
    main()
