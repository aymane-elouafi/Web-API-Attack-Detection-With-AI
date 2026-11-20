"""Build models/schema.json for the gateway's schema detector.

    python -m wafgw.schema_learn --dataset data/dataset.csv            # learn from the normal rows
    python -m wafgw.schema_learn --events data/waf.db                  # learn from allowed gateway events (use a clean window!)
    python -m wafgw.schema_learn --openapi http://127.0.0.1:8000/openapi.json   # or a file; no traffic needed
    ... combine: learned endpoints fill in, the OpenAPI spec wins on the endpoints it defines.

The learning window must be clean: an attack present in the window and repeated at least
`min_support` times looks like normal behaviour. Use monitor mode on trusted traffic, or an OpenAPI spec.
"""
import argparse
import json
import sqlite3
from pathlib import Path

import httpx
import pandas as pd

from detection.schema import SchemaModel


def load_openapi(src: str) -> dict:
    return httpx.get(src, timeout=10).json() if src.startswith("http") else json.loads(Path(src).read_text())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset")
    ap.add_argument("--events")
    ap.add_argument("--openapi")
    ap.add_argument("--out", default="models/schema.json")
    ap.add_argument("--min-support", type=int, default=5)
    args = ap.parse_args()
    if not (args.dataset or args.events or args.openapi):
        ap.error("give at least one of --dataset, --events, --openapi")

    model = SchemaModel(min_support=args.min_support)
    if args.dataset:
        d = pd.read_csv(args.dataset, keep_default_na=False)
        model.learn(d[d.label == 0][["method", "path", "query", "body"]].itertuples(index=False, name=None))
    if args.events:
        rows = sqlite3.connect(args.events).execute(
            "SELECT method, path, query, body_snippet FROM events WHERE action = 'allowed' AND risk < 0.2").fetchall()
        model.learn(rows)
    if args.openapi:
        model.endpoints.update(SchemaModel.from_openapi(load_openapi(args.openapi)).endpoints)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(model.to_json())
    print(f"{len(model.endpoints)} endpoints written to {args.out}")


if __name__ == "__main__":
    main()
