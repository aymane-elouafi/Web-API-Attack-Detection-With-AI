"""Closed-loop load test: N concurrent clients send ordinary requests for D seconds; prints req/s and latency percentiles.

    python -m traffic.loadtest --url http://127.0.0.1:8080 [--concurrency 32] [--seconds 10] [--attack-share 0.05]

Run it once against the app directly and once through the gateway to get the gateway's own overhead. The load
generator is one Python process: on a small machine it, not the gateway, can be the limit (watch its CPU).
Every request uses a fresh X-Forwarded-For (needs WAFGW_TRUST_FORWARDED=1 on the gateway) so rate limits and
per-client behavior state do not distort the measurement.
"""
import argparse
import asyncio
import random
import time

import httpx
import numpy as np

PATHS = [("GET", "/products/search?q={w}"), ("GET", "/products/{n}"), ("GET", "/health"), ("GET", "/products/search?q={w}+{w}")]
WORDS = ["shoes", "laptop", "red", "phone", "book", "lamp", "chair", "tea", "o-brien", "50%25+off"]
ATTACKS = ["/products/search?q=1'+OR+'1'='1", "/products/search?q=<script>alert(1)</script>", "/files?name=../../etc/passwd"]


async def worker(c, end, rng, lat, codes, attack_share):
    while time.perf_counter() < end:
        if rng.random() < attack_share:
            m, u = "GET", rng.choice(ATTACKS)
        else:
            m, u = rng.choice(PATHS)
            u = u.format(w=rng.choice(WORDS), n=rng.randint(1, 50))
        t = time.perf_counter()
        try:
            r = await c.request(m, u, headers={"X-Forwarded-For": f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                                               "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "Accept": "*/*", "Accept-Language": "en"})
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
        except httpx.HTTPError:
            codes["error"] = codes.get("error", 0) + 1
            continue
        lat.append((time.perf_counter() - t) * 1000)


async def run(url, concurrency, seconds, attack_share, seed=1):
    lat, codes = [], {}
    async with httpx.AsyncClient(base_url=url, timeout=30, limits=httpx.Limits(max_connections=concurrency)) as c:
        end = time.perf_counter() + seconds
        t0 = time.perf_counter()
        await asyncio.gather(*(worker(c, end, random.Random(seed + i), lat, codes, attack_share) for i in range(concurrency)))
        took = time.perf_counter() - t0
    a = np.array(lat) if lat else np.zeros(1)
    return {"req/s": round(len(lat) / took), "p50 ms": round(float(np.percentile(a, 50)), 1), "p95 ms": round(float(np.percentile(a, 95)), 1),
            "p99 ms": round(float(np.percentile(a, 99)), 1), "responses": codes}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--attack-share", type=float, default=0.0)
    a = ap.parse_args()
    print(asyncio.run(run(a.url, a.concurrency, a.seconds, a.attack_share)))


if __name__ == "__main__":
    main()
