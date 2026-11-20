"""Management console for the WAF gateway (live events, policies, learning inbox, simulator, threats, alerts)
plus the offline Evaluation page (detector comparison on the labeled dataset).

    WAF_ADMIN_TOKEN=... .venv/bin/python -m dashboard        then open http://127.0.0.1:8100

The Evaluation page reads data/dataset.csv and data/predictions_*.csv; ground-truth labels are shown as "truth".
Everything under /api/eval is that offline view; the rest talks to the gateway admin API (dashboard/console.py).
"""
import asyncio
import contextlib
from functools import cache
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from detection import metrics
from detection.fusion import fuse, strengths
from dashboard import console
from detection.run_fusion import load

STATIC = Path(__file__).with_name("static")


@contextlib.asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(console.alert_worker())
    yield
    task.cancel()


app = FastAPI(title="WAF console", lifespan=lifespan)


@app.middleware("http")
async def login_wall(request: Request, call_next):
    open_paths = ("/api/session", "/api/login", "/api/logout")
    if request.url.path.startswith("/api/") and request.url.path not in open_paths and not console.authorized(request):
        return JSONResponse({"detail": "login required"}, 401)
    resp = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        resp.headers["cache-control"] = "no-cache"          # always revalidate: the UI files change with the code
    return resp


app.include_router(console.router)
DETECTORS = {"rules": "rule_flag", "Coraza": "waf_flag", "payload ML": "ml_flag", "behavior ML": "beh_flag"}


@cache
def frame() -> tuple[pd.DataFrame, pd.DataFrame]:
    df = load()
    hits = pd.read_csv("data/predictions_rules.csv", keep_default_na=False)[["id", "rule_hits"]]
    df = df.merge(hits, on="id").sort_values("ts").reset_index(drop=True)   # row position = replay order
    parts = strengths(df)
    df["risk"] = fuse(parts)
    return df, parts


def decided(threshold: float) -> pd.DataFrame:
    df = frame()[0].copy()
    df["hybrid"] = df.risk >= threshold
    return df


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/api/eval/summary")
def summary(threshold: float = 0.5):
    df = decided(threshold)
    flags = {**DETECTORS, "hybrid": "hybrid"}
    detectors = []
    for name, col in flags.items():
        m = metrics.overall(df, col)
        detectors.append({"name": name, "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
                          "caught": int(m["tp"]), "missed": int(m["fn"]), "false_alarms": int(m["fp"])})
    by_type = pd.DataFrame({"attacks": metrics.by_attack_type(df, "hybrid")["attacks"]} |
                           {n: metrics.by_attack_type(df, c)["recall"] for n, c in flags.items()})
    return {"requests": len(df), "attacks": int(df.label.sum()), "detectors": detectors,
            "by_type": by_type.reset_index().to_dict("records")}


@app.get("/api/eval/alerts")
def alerts(threshold: float = 0.5, show: str = "flagged", limit: int = 100):
    """show: flagged | missed (attacks nobody flagged) | false_alarms."""
    df = decided(threshold)
    parts = frame()[1]
    pick = {"flagged": df.hybrid, "missed": (df.label == 1) & ~df.hybrid,
            "false_alarms": (df.label == 0) & df.hybrid}[show]
    out = df[pick].sort_values("risk", ascending=False).head(limit)
    return {"total": int(pick.sum()), "shown": len(out), "rows": rows_of(out, parts)}


def rows_of(rows: pd.DataFrame, parts: pd.DataFrame) -> list[dict]:
    """JSON rows for the alert list, client timeline and live feed."""
    return [{"id": int(r.id), "ts": float(r.ts), "client": r.client_ip, "method": r.method,
             "request": f"{r.path}?{r.query}" if r.query else r.path, "body": r.body, "status": int(r.status),
             "risk": round(float(r.risk), 3), "truth": r.attack_type, "hybrid": bool(r.hybrid),
             "flags": [n for n, c in DETECTORS.items() if r[c]],
             "why": {k: round(float(v), 2) for k, v in parts.loc[i].items() if v >= 0.1},
             "rule_hits": r.rule_hits, "coraza_rules": r.waf_rules} for i, r in rows.iterrows()]


@app.get("/api/eval/clients")
def clients(threshold: float = 0.5, limit: int = 200):
    """Clients ranked by their riskiest request."""
    df = decided(threshold)
    g = df.groupby("client_ip")
    out = pd.DataFrame({"requests": g.size(), "flagged": g.hybrid.sum(), "attacks": g.label.sum(),
                        "max_risk": g.risk.max().round(3), "mean_risk": g.risk.mean().round(3),
                        "truth": g.attack_type.agg(lambda t: ", ".join(sorted(set(t) - {"normal"})) or "normal")})
    out = out.sort_values(["max_risk", "mean_risk"], ascending=False).head(limit)
    return {"total": int(g.ngroups), "rows": [{"client": ip, **r} for ip, r in out.to_dict("index").items()]}


@app.get("/api/eval/client")
def client_timeline(ip: str, threshold: float = 0.5):
    df = decided(threshold)
    return {"client": ip, "rows": rows_of(df[df.client_ip == ip], frame()[1])}


@app.get("/api/eval/feed")
def feed(after: int = -1, n: int = 20, threshold: float = 0.5):
    """Replay in time order: rows after position `after`; send back `next` as the new cursor."""
    df = decided(threshold)
    out = df.iloc[after + 1:after + 1 + max(1, min(n, 200))]
    return {"next": int(out.index[-1]) if len(out) else after, "done": bool(len(out) == 0),
            "rows": rows_of(out, frame()[1])}
