"""Paced replay of data/dataset.csv through a gateway, so a demo behaves like real traffic.

    WAFGW_TRUST_FORWARDED=1 python -m wafgw                       # the gateway must read each client's IP
    python -m traffic.replay --url http://127.0.0.1:8080 --rate 5 --seed 1 --report

data/dataset.csv is only read, never written (unlike traffic.generate). Every session keeps its real
gaps between requests (a shopper clicks every few seconds, a brute-force tool every 0.2 s), divided
by --speed; only the START of each session is moved, shuffled so that sessions overlap and the whole
replay averages --rate requests per second. Logins are re-done live: the API issues fresh tokens.
--report joins what the gateway decided (its event database) with the dataset labels.
"""
import argparse
import asyncio
import csv
import json
import random
import sqlite3
import time
from collections import Counter, defaultdict

import httpx

HOST = "shop.example.test"
SESSION_GAP = 300      # seconds of silence (dataset time) that end a client's session


def load_sessions(path: str) -> list[list[dict]]:
    by_ip = defaultdict(list)
    for r in csv.DictReader(open(path, newline="", encoding="utf-8")):
        r["ts"] = float(r["ts"])
        by_ip[r["client_ip"]].append(r)
    sessions = []
    for rows in by_ip.values():
        rows.sort(key=lambda r: r["ts"])
        cur = [rows[0]]
        for r in rows[1:]:
            if r["ts"] - cur[-1]["ts"] > SESSION_GAP:
                sessions.append(cur)
                cur = []
            cur.append(r)
        sessions.append(cur)
    return sessions


def schedule(sessions: list[list[dict]], rate: float, speed: float, seed: int) -> list[tuple[float, list[tuple[float, dict]]]]:
    """[(session start, [(offset, row), ...])] with starts spread so the replay averages `rate` req/s."""
    rng = random.Random(seed)
    total = sum(map(len, sessions))
    duration = total / rate
    out = []
    for s in sessions:
        offsets = [(r["ts"] - s[0]["ts"]) / speed for r in s]
        start = rng.uniform(0, max(0.0, duration - offsets[-1]))
        out.append((start, list(zip(offsets, s))))
    return sorted(out, key=lambda x: x[0])


async def play(url: str, plan, sent: dict, status: Counter) -> None:
    tokens: dict[tuple[str, str], str] = {}
    t0 = time.monotonic()

    async def session(http: httpx.AsyncClient, start: float, steps) -> None:
        for offset, r in steps:
            await asyncio.sleep(max(0.0, t0 + start + offset - time.monotonic()))
            headers = {"User-Agent": r["user_agent"], "X-Forwarded-For": r["client_ip"], "Host": HOST}
            if r["user"] and (r["client_ip"], r["user"]) in tokens:
                headers["Authorization"] = "Bearer " + tokens[(r["client_ip"], r["user"])]
            target = r["path"] + ("?" + r["query"] if r["query"] else "")
            try:
                resp = await http.request(r["method"], target, content=r["body"] or None, headers={
                    **headers, **({"Content-Type": "application/json"} if r["body"] else {})})
            except httpx.HTTPError:
                status["error"] += 1
                continue
            status[resp.status_code] += 1
            if rid := resp.headers.get("x-waf-request-id"):
                sent[rid] = (r["label"], r["attack_type"])
            if r["path"] == "/login" and resp.status_code == 200:
                data = resp.json()
                tokens[(r["client_ip"], data["user"])] = data["token"]

    async with httpx.AsyncClient(base_url=url, timeout=20, verify=False, limits=httpx.Limits(max_connections=200)) as http:
        await asyncio.gather(*(session(http, start, steps) for start, steps in plan))


def report(db: str, sent: dict) -> None:
    time.sleep(1.5)                                          # the gateway writes its log in the background
    con = sqlite3.connect(db)
    ids = list(sent)
    rows = []
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        rows += con.execute(f"SELECT request_id, action, detectors FROM events WHERE request_id IN ({','.join('?' * len(chunk))})", chunk).fetchall()
    flagged = {"blocked", "would_block"}
    benign = [(a, json.loads(d)) for rid, a, d in rows if sent[rid][0] == "0"]
    caught, seen = Counter(), Counter()
    for rid, a, _ in rows:
        label, kind = sent[rid]
        if label == "1":
            seen[kind] += 1
            caught[kind] += a in flagged
    fp = [d for a, d in benign if a in flagged]
    by_detector = Counter(n for d in fp for n, s in d.items() if s >= 0.5)
    print(f"\nGateway decisions for {len(rows)} logged requests ({len(sent) - len(rows)} not found in {db})")
    print(f"  benign flagged: {len(fp)} of {len(benign)} ({len(fp) / max(1, len(benign)):.1%})   by detector: {dict(by_detector) or 'none'}")
    print(f"  attacks caught: {sum(caught.values())} of {sum(seen.values())} ({sum(caught.values()) / max(1, sum(seen.values())):.1%})")
    for kind in sorted(seen):
        print(f"    {kind:16} {caught[kind]:4} / {seen[kind]:<4} {caught[kind] / seen[kind]:.0%}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--data", default="data/dataset.csv")
    ap.add_argument("--rate", type=float, default=5, help="average requests per second over the whole replay")
    ap.add_argument("--speed", type=float, default=1, help="divides the gaps inside a session (10 = ten times faster clicks)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--loop", action="store_true", help="repeat forever with a new shuffle each round (Ctrl-C to stop)")
    ap.add_argument("--report", nargs="?", const="data/waf.db", metavar="DB", help="afterwards compare gateway decisions with labels")
    args = ap.parse_args()

    sessions = load_sessions(args.data)
    n = sum(map(len, sessions))
    print(f"{n} requests in {len(sessions)} sessions -> {args.url}, ~{args.rate} req/s (~{n / args.rate / 60:.1f} min per round)")
    round_ = 0
    try:
        while True:
            sent, status = {}, Counter()
            asyncio.run(play(args.url, schedule(sessions, args.rate, args.speed, args.seed + round_), sent, status))
            print(f"round {round_ + 1} done: {dict(status)}")
            round_ += 1
            if not args.loop:
                break
    except KeyboardInterrupt:
        print("stopped")
    if args.report and sent:
        report(args.report, sent)


if __name__ == "__main__":
    main()
