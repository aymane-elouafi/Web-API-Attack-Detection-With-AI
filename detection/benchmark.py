"""Head-to-head benchmark: our detectors vs Coraza + OWASP CRS (the engine behind BunkerWeb / ModSecurity setups)
at paranoia levels 1-4, on traffic none of them was tuned on (CSIC 2010, held-out).

    docker run -d --rm -e INSPECT_ONLY=1 -e PARANOIA=1 -e LISTEN=0.0.0.0:8080 -p 127.0.0.1:8191:8080 web-api-coraza:local   (levels 1-4 on ports 8191-8194)
    python -m detection.benchmark [--ports 8191 8192 8193 8194] [--out docs/BENCHMARK.md]

Protocol (same as detection/run_schema.py): normal CSIC requests are de-duplicated and split 50/50; our schema detector
learns from one half; EVERYTHING is scored on the unseen normals + all anomalies. Coraza gets the same requests with
ordinary browser headers (CSIC keeps no headers, and bare requests would trip CRS "missing header" rules unfairly).
"""
import argparse
import asyncio

import httpx
import numpy as np
import pandas as pd

from detection.external_data import dedupe, load_csic
from detection.metrics import overall
from detection.report import pct
from detection.rules import THRESHOLD as RULE_THRESHOLD, stateless_hits
from detection.run_schema import ALERT, requests, run
from detection.schema import SchemaModel

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "Accept": "text/html,*/*;q=0.8",
           "Accept-Language": "en-US,en;q=0.5", "Host": "shop.example"}


async def coraza(df: pd.DataFrame, port: int, workers: int = 48) -> np.ndarray:
    """1 where Coraza+CRS would block (anomaly score >= 5)."""
    sem, out = asyncio.Semaphore(workers), np.zeros(len(df), dtype=int)
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=30, limits=httpx.Limits(max_connections=workers)) as c:
        async def one(i, r):
            async with sem:
                h = dict(HEADERS)
                if r.body:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                resp = await c.request(r.method, r.path + ("?" + r.query if r.query else ""), content=r.body.encode("utf-8", "ignore") or None, headers=h)
                out[i] = int(resp.headers.get("x-waf-block", "0") == "1")
        await asyncio.gather(*(one(i, r) for i, r in enumerate(df.itertuples(index=False))))
    return out


def row(name: str, df: pd.DataFrame, flag: str, ms: str = "") -> dict:
    m = overall(df, flag)
    return {"detector": name, "recall": pct(m["recall"]), "precision": pct(m["precision"]), "false alarms": f"{m['fp']} ({pct(m['fpr'])})", "notes": ms}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", nargs="*", type=int, default=[8191, 8192, 8193, 8194], help="Coraza containers for paranoia 1..4")
    ap.add_argument("--payload-model", default="models/payload.joblib")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    import joblib

    csic = dedupe(load_csic())
    normal, attack = csic[csic.label == 0], csic[csic.label == 1]
    learn = normal.sample(frac=0.5, random_state=0)
    test = pd.concat([normal.drop(learn.index), attack]).reset_index(drop=True)
    schema = SchemaModel().learn(requests(learn))
    res = run(schema, test)
    from detection.ml_payload import prepare
    texts, nums = prepare(res)
    res["ml"] = joblib.load(args.payload_model).score(texts, nums)
    res["rules"] = [sum(s for _, s in stateless_hits(r.query, r.body)) for r in res.itertuples()]
    res["ml_flag"], res["rules_flag"] = res.ml >= 0.5, res.rules >= RULE_THRESHOLD
    res["fused"] = 1 - (1 - res.schema) * (1 - res.ml) * (1 - np.clip(res.rules / 10, 0, 1))
    res["ours_flag"] = res.fused >= ALERT
    res["ours_text_flag"] = (1 - (1 - res.ml) * (1 - np.clip(res.rules / 10, 0, 1))) >= ALERT

    rows = []
    for pl, port in enumerate(args.ports, 1):
        res[f"pl{pl}"] = asyncio.run(coraza(res, port)).astype(bool)
        rows.append(row(f"Coraza + CRS, paranoia {pl}", res, f"pl{pl}", "BunkerWeb / ModSecurity engine"))
    rows += [row("our rules", res, "rules_flag"), row("our payload model (parser tokens + n-grams)", res, "ml_flag"),
             row("our schema detector (learned from 50% of normals)", res, "schema_flag"),
             row("ours: rules + payload model (no app learning)", res, "ours_text_flag"),
             row("ours: rules + payload model + schema (full)", res, "ours_flag", "needs learning traffic or an OpenAPI spec")]
    if args.ports:
        res["best_pl_or_ours"] = res.ours_flag | res[f"pl{len(args.ports)}"]
    table = pd.DataFrame(rows).set_index("detector")
    atk = res[res.label == 1]
    by = atk.assign(kind=np.where(atk.attack_type == "other", "structural (no attack text)", atk.attack_type)).groupby("kind")
    cls = pd.DataFrame({"count": by.size(), **{f"CRS PL{i}": by[f"pl{i}"].mean().map(pct) for i in range(1, len(args.ports) + 1)},
                        "ours (full)": by.ours_flag.mean().map(pct)})
    md = (f"CSIC 2010, held-out: {int((res.label == 0).sum())} unseen normal + {len(atk)} anomalous requests (de-duplicated).\n\n"
          + "```\n" + table.to_string() + "\n```\n\nRecall by anomaly type (type guessed from the text by regex, only for reporting):\n\n```\n" + cls.to_string() + "\n```\n")
    print(md)
    if args.out:
        open(args.out, "w").write(md)


if __name__ == "__main__":
    main()
