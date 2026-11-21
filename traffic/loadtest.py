"""Closed-loop load test: N concurrent clients send ordinary requests for D seconds; prints req/s and latency percentiles.

    python -m traffic.loadtest --url http://127.0.0.1:8080 [--concurrency 32] [--seconds 10] [--attack-share 0.05]

Run it once against the app directly and once through the gateway to get the gateway's own overhead. The load
generator is one Python process on bare asyncio sockets (httpx alone tops out near 350 req/s here, which would hide the gateway):
run several copies at once to push a multi-worker gateway, and watch their CPU.
Every request uses a fresh X-Forwarded-For (needs WAFGW_TRUST_FORWARDED=1 on the gateway) so rate limits and
per-client behavior state do not distort the measurement.
"""
import argparse
import asyncio
import random
import time

import numpy as np

PATHS = [("GET", "/products/search?q={w}"), ("GET", "/products/{n}"), ("GET", "/health"), ("GET", "/products/search?q={w}+{w}")]
WORDS = ["shoes", "laptop", "red", "phone", "book", "lamp", "chair", "tea", "o-brien", "50%25+off"]
ATTACKS = ["/products/search?q=1'+OR+'1'='1", "/products/search?q=<script>alert(1)</script>", "/files?name=../../etc/passwd"]


async def fetch(conn, method, target, host, ip):
    """One keep-alive HTTP/1.1 request on a raw connection; returns the status code."""
    r, w = conn
    w.write(f"{method} {target} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: {ip}\r\nAccept: */*\r\nAccept-Language: en\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0\r\n\r\n".encode())
    head = (await r.readuntil(b"\r\n\r\n")).lower()
    if b"transfer-encoding: chunked" in head:
        await r.readuntil(b"0\r\n\r\n")
    elif b"content-length:" in head:
        await r.readexactly(int(head.split(b"content-length:")[1].split(b"\r\n")[0]))
    return int(head[9:12])


async def worker(host, port, end, rng, lat, codes, attack_share):
    conn = await asyncio.open_connection(host, port)
    while time.perf_counter() < end:
        if rng.random() < attack_share:
            m, u = "GET", rng.choice(ATTACKS)
        else:
            m, u = rng.choice(PATHS)
            u = u.format(w=rng.choice(WORDS), n=rng.randint(1, 50))
        t = time.perf_counter()
        try:
            code = await fetch(conn, m, u, f"{host}:{port}", f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}")
            codes[code] = codes.get(code, 0) + 1
        except (OSError, asyncio.IncompleteReadError, ValueError):
            codes["error"] = codes.get("error", 0) + 1
            conn = await asyncio.open_connection(host, port)             # the server closed it: start a new one
            continue
        lat.append((time.perf_counter() - t) * 1000)


async def run(url, concurrency, seconds, attack_share, seed=1):
    lat, codes = [], {}
    host, _, port = url.split("//")[-1].rstrip("/").partition(":")
    end = time.perf_counter() + seconds
    t0 = time.perf_counter()
    await asyncio.gather(*(worker(host, int(port or 80), end, random.Random(seed + i), lat, codes, attack_share) for i in range(concurrency)))
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
