"""Train the two AI models from the labeled dataset and save them for the gateway.

    python -m wafgw.train [--data data/dataset.csv] [--out models] [--synthetic-only]

The payload model is trained on the real-world data in data/external/ (see data/external/SOURCES.md)
plus the synthetic dataset when that folder exists; --synthetic-only (or no data/external/) falls back
to the synthetic dataset alone. CSIC 2010 stays out of training: it is the held-out test set.
"""
import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from detection.ml_behavior import ALERT_SHARE, behavior_features
from detection.ml_payload import PayloadModel, fit_full, prepare


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--out", default="models")
    ap.add_argument("--synthetic-only", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(args.data, keep_default_na=False)

    if args.synthetic_only or not Path("data/external/fwaf").exists():
        model = fit_full(df)
    else:
        from detection.external_data import load_all
        train, _ = load_all()
        texts, nums = prepare(train)
        model = PayloadModel().fit(texts, nums, train.label.to_numpy())
        print(f"payload model trained on {len(train)} real+synthetic requests")
    joblib.dump(model, out / "payload.joblib")

    feats = behavior_features(df)
    forest = IsolationForest(n_estimators=100, random_state=0).fit(feats)   # 100 trees: low per-request latency
    scores = -forest.score_samples(feats)
    flagged = scores >= np.quantile(scores, 1 - ALERT_SHARE)
    cutoff = float(pd.Series(scores).rank(pct=True)[flagged].min())          # percentile where the model alerts
    joblib.dump({"forest": forest, "sorted_scores": np.sort(scores), "cutoff": cutoff}, out / "behavior.joblib")
    print(f"saved {out}/payload.joblib and {out}/behavior.joblib (behavior alert percentile {cutoff:.3f})")


if __name__ == "__main__":
    main()
