# Performance (first measurement)

Reproduce: `python -m traffic.loadtest --url <url> --concurrency N --seconds 8` against the demo API directly (:8000) and through the
gateway (:8080, monitor mode, `WAFGW_TRUST_FORWARDED=1`). One machine, 8 cores, shared by the load generator (one Python
process), the demo API (one process, SQLite) and the gateway (one process). Plain GET traffic, random client IPs.

| concurrency | direct req/s | direct p50 / p99 | gateway req/s | gateway p50 / p99 |
|---|---|---|---|---|
| 1 | 437 | 2.0 / 4.1 ms | 127 | 8.2 / 12.5 ms |
| 16 | 506 | 16.7 / 156 ms | 326 | 39.4 / 160 ms |
| 64 | 247 | 157 / 1360 ms | 189 | 214 / 1530 ms |
| 16, 5% attacks | - | - | 346 | 36.5 / 142 ms |

## What this says (and does not)

* **The gateway adds about 6 ms at low load** (8.2 vs 2.0 ms p50) and holds roughly **300-350 requests per second per process** here.
  Enterprise WAFs are measured in tens of thousands per second per node. We are far from that, and this is the biggest gap to close.
* The demo API is itself one slow Python process, and the load generator shares the CPU, so under heavy concurrency all three
  compete and the numbers say more about this laptop than about the gateway. Treat them as a floor, not a limit.
* Not measured: large bodies, TLS, HTTP/2, Coraza side-car on, many gateway workers, long runs, memory growth.

## Found and fixed while measuring

Per-request work in the behavior features and the bot detector looped over a client's whole 60 s history, so one busy IP
(a NAT, an office, an attacker) made every request slower. Histories are now capped at 500 requests per client
(`wafgw/engine.py`, `wafgw/bot.py`). The loops are still linear in that cap; incremental counters would remove them.

## Next steps toward real throughput

1. Several gateway worker processes behind one port, with rate limits and behavior windows in shared state (Redis).
2. Profile the proxy path: streaming, logging and header handling cost more than detection (detection is about 2 ms on new text, 0.3 ms cached).
3. Consider moving the data plane to a compiled proxy (Go or Rust) and keeping Python only for scoring.
