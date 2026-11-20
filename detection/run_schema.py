"""Evaluate the API schema detector.

    python -m detection.run_schema [--openapi http://127.0.0.1:8000/openapi.json]

(a) CSIC 2010 (real-format traffic of one shop): normal requests are de-duplicated and split 50/50
    (seeded); the schema is learned from the first half only and tested on the other half plus ALL
    anomalies; then combined with the payload model and the rules; then re-run with poisoned learning data.
(b) The project's demo dataset: learn from normal rows of half the clients, test on the other half.
(c) OpenAPI: the schema comes from the demo API's spec, no traffic is learned.
"""
import argparse
import json
from collections import Counter

import numpy as np
import pandas as pd

from detection import metrics
from detection.external_data import classify, dedupe, load_csic
from detection.ml_payload import prepare
from detection.report import pct
from detection.rules import THRESHOLD as RULE_THRESHOLD, stateless_hits
from detection.schema import SchemaModel

ALERT = 0.5


def requests(df: pd.DataFrame):
    return list(df[["method", "path", "query", "body"]].itertuples(index=False, name=None))


def run(model: SchemaModel, df: pd.DataFrame) -> pd.DataFrame:
    """Add columns: schema (strength), kinds (list of finding kinds)."""
    found = [model.score(*r) for r in requests(df)]
    out = df.copy()
    out["schema"] = [model.strength(f) for f in found]
    out["kinds"] = [[x["kind"] for x in f] for f in found]
    out["schema_flag"] = out.schema >= ALERT
    return out


def line(name: str, df: pd.DataFrame, flag: str) -> dict:
    m = metrics.overall(df, flag)
    return {"": name, "precision": pct(m["precision"]), "recall": pct(m["recall"]), "false alarms": f"{m['fp']} ({pct(m['fpr'])})"}


def kind_table(df: pd.DataFrame) -> pd.DataFrame:
    """Share of attacks where each finding kind appeared (any strength) / the schema alone alerted."""
    attacks = df[df.label == 1]
    kinds = Counter(k for ks in attacks.kinds for k in set(ks))
    return pd.DataFrame({"attacks with this finding": {k: f"{n} ({pct(n / len(attacks))})" for k, n in kinds.most_common()}})


# --- (a) CSIC 2010 ---------------------------------------------------------------------------------
def csic_section(payload_model) -> None:
    csic = dedupe(load_csic())
    normal, attack = csic[csic.label == 0], csic[csic.label == 1]
    learn_n = normal.sample(frac=0.5, random_state=0)
    test = pd.concat([normal.drop(learn_n.index), attack])
    print(f"CSIC 2010 after de-duplication: {len(normal)} normal, {len(attack)} anomalous. "
          f"Learn from {len(learn_n)} normal requests; test on {len(test) - len(attack)} unseen normal + {len(attack)} anomalies.\n")

    model = SchemaModel().learn(requests(learn_n))
    print(f"learned {len(model.endpoints)} endpoints (a one-off page seen fewer than 5 times is not accepted)\n")
    res = run(model, test)
    res["structural"] = (res.label == 1) & (res.attack_type == "other")     # no payload text found by the regexes

    # payload model, rules, and everything fused (noisy-OR, flag at 0.5 as in the gateway)
    texts, nums = prepare(res)
    res["ml"] = payload_model.score(texts, nums) if payload_model else 0.0
    res["rules"] = [sum(s for _, s in stateless_hits(r.query, r.body)) for r in res.itertuples()]
    res["ml_flag"], res["rules_flag"] = res.ml >= 0.5, res.rules >= RULE_THRESHOLD
    res["fused"] = 1 - (1 - res.schema) * (1 - res.ml) * (1 - np.clip(res.rules / 10, 0, 1))
    res["fused_flag"], res["no_schema_flag"] = res.fused >= ALERT, (1 - (1 - res.ml) * (1 - np.clip(res.rules / 10, 0, 1))) >= ALERT
    print(pd.DataFrame([line("schema alone", res, "schema_flag"), line("payload ML alone", res, "ml_flag"), line("rules alone", res, "rules_flag"),
                        line("rules + payload ML (before)", res, "no_schema_flag"),
                        line("rules + payload ML + schema (after)", res, "fused_flag")]).set_index("").to_string())

    atk = res[res.label == 1]
    print("\nRecall by what the anomaly is (type guessed from the text by regex, only for reporting):")
    by = atk.assign(kind=np.where(atk.attack_type == "other", "structural (no attack text)", atk.attack_type)).groupby("kind")
    print(pd.DataFrame({"count": by.size(), "schema": by.schema_flag.mean().map(pct), "payload ML": by.ml_flag.mean().map(pct),
                        "rules": by.rules_flag.mean().map(pct), "all three": by.fused_flag.mean().map(pct)}).to_string())
    print("\nWhich schema findings fire on the anomalies:")
    print(kind_table(res).to_string())
    fp = res[(res.label == 0) & res.schema_flag]
    print(f"\nSchema false alarms: {len(fp)} normal requests; by finding: {dict(Counter(k for ks in fp.kinds for k in set(ks)))}")
    for r in fp.head(3).itertuples():
        print(f"  {r.method} {r.path}?{r.query[:80]}  -> {r.kinds}")
    misses = atk[~atk.fused_flag]
    print(f"\nStill missed after fusion: {len(misses)} of {len(atk)} anomalies. Examples:")
    for r in misses.sample(min(4, len(misses)), random_state=1).itertuples():
        print(f"  {r.method} {r.path}?{r.query[:90]}")

    print("\nPoisoned learning data (anomalies mixed into the learning half), evaluated on the same test requests:")
    rows, held = [], test[test.label == 0]
    for share in (0.0, 0.05, 0.20):
        poison = attack.sample(int(share * len(learn_n)), random_state=1)
        m2 = SchemaModel().learn(requests(pd.concat([learn_n, poison])))
        r2 = run(m2, pd.concat([held, attack.drop(poison.index)]))
        rows.append({"poison in learning window": f"{share:.0%}", **{k: v for k, v in line("", r2, "schema_flag").items() if k}})
    print(pd.DataFrame(rows).set_index("poison in learning window").to_string())


# --- (b) demo dataset ----------------------------------------------------------------------------------
def demo_section(path: str) -> None:
    d = pd.read_csv(path, keep_default_na=False)
    ips = sorted(d.client_ip.unique())
    learn_ips = set(np.random.default_rng(0).choice(ips, len(ips) // 2, replace=False))
    learn = d[d.client_ip.isin(learn_ips) & (d.label == 0)]
    test = d[~d.client_ip.isin(learn_ips)]
    model = SchemaModel().learn(requests(learn))
    res = run(model, test)
    print(f"Demo dataset: learned from {len(learn)} normal requests of {len(learn_ips)} clients; tested on {len(test)} requests of the other clients.\n")
    print(pd.DataFrame([line("schema alone", res, "schema_flag")]).set_index("").to_string())
    by = res.groupby("attack_type")
    print("\nShare of requests flagged by the schema detector, by truth label:")
    print(pd.DataFrame({"requests": by.size(), "flagged": by.schema_flag.mean().map(pct)}).to_string())
    print("(BOLA and brute force are behavior attacks: any flags there are side effects, not a claim.)")
    fp = res[(res.label == 0) & res.schema_flag]
    print(f"False alarms: {len(fp)} of {int((res.label == 0).sum())}; by finding {dict(Counter(k for ks in fp.kinds for k in set(ks)))}")
    ma = res[(res.attack_type == "mass_assignment") & ~res.schema_flag]
    print(f"Mass assignment missed: {len(ma)} of {int((res.attack_type == 'mass_assignment').sum())}")


# --- (c) OpenAPI ---------------------------------------------------------------------------------------------
def openapi_section(src: str, dataset: str) -> None:
    from wafgw.schema_learn import load_openapi
    model = SchemaModel.from_openapi(load_openapi(src))
    print(f"Schema from {src}: {len(model.endpoints)} endpoints, no learning.\n")
    cases = [("valid", "GET", "/orders/5", "", ""), ("valid", "GET", "/products/search", "q=laptop", ""),
             ("valid", "POST", "/login", "", json.dumps({"username": "user1", "password": "x"})),
             ("valid", "PUT", "/users/me", "", json.dumps({"email": "a@b.co"})),
             ("valid", "POST", "/comments", "", json.dumps({"text": "hello"})),
             ("attack", "PUT", "/users/me", "", json.dumps({"email": "a@b.co", "role": "admin"})),
             ("attack", "PUT", "/users/me", "", json.dumps({"is_admin": True})),
             ("attack", "POST", "/login", "", json.dumps({"username": "a"})),
             ("attack", "GET", "/orders/5", "debug=1", ""), ("attack", "DELETE", "/orders/5", "", ""),
             ("attack", "GET", "/admin/users", "", ""), ("attack", "GET", "/orders/abc", "", "")]
    for tag, m, p, q, b in cases:
        f = model.score(m, p, q, b)
        print(f"  {tag:6} {m:6} {p}{'?' + q if q else ''} {b[:40]:40} -> {model.strength(f):.2f} {[x['kind'] + ':' + x['param'] for x in f]}")
    d = pd.read_csv(dataset, keep_default_na=False)
    res = run(model, d)
    by = res.groupby("attack_type")
    print("\nWhole demo dataset against the spec alone (share flagged):")
    print(pd.DataFrame({"requests": by.size(), "flagged": by.schema_flag.mean().map(pct)}).to_string())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/dataset.csv")
    ap.add_argument("--payload-model", default="models/payload.joblib")
    ap.add_argument("--openapi", default="")
    args = ap.parse_args()
    import joblib
    from pathlib import Path
    pm = joblib.load(args.payload_model) if Path(args.payload_model).exists() else None
    print("=" * 30, "(a) CSIC 2010")
    csic_section(pm)
    print("\n" + "=" * 30, "(b) demo dataset")
    demo_section(args.dataset)
    if args.openapi:
        print("\n" + "=" * 30, "(c) OpenAPI")
        openapi_section(args.openapi, args.dataset)


if __name__ == "__main__":
    main()
