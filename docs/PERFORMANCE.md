# Performance

Reproduce: `python -m traffic.loadtest --url <url> --concurrency N --seconds 8` against the demo API directly (:8000) and through the
gateway (:8080, monitor mode, `WAFGW_TRUST_FORWARDED=1`). One machine, 8 cores, shared by the load generator (one Python
process), the demo API (one process, SQLite) and the gateway (one process). Plain GET traffic, random client IPs.

| concurrency | direct req/s | direct p50 / p99 | gateway req/s | gateway p50 / p99 |
|---|---|---|---|---|
| 1 | 437 | 2.0 / 4.1 ms | 127 | 8.2 / 12.5 ms |
| 16 | 506 | 16.7 / 156 ms | 326 | 39.4 / 160 ms |
| 64 | 247 | 157 / 1360 ms | 189 | 214 / 1530 ms |
| 16, 5% attacks | - | - | 346 | 36.5 / 142 ms |

*The table above was measured with an `httpx` load generator, which turned out to be the limit (see "Measurement mistakes"); the multi-worker table below is the better one.*

## What this says (and does not)

* **The gateway adds about 6 ms at low load** (8.2 vs 2.0 ms p50) and holds roughly **300-350 requests per second per process** here.
  Enterprise WAFs are measured in tens of thousands per second per node. We are far from that, and this is the biggest gap to close.
* The demo API is itself one slow Python process, and the load generator shares the CPU, so under heavy concurrency all three
  compete and the numbers say more about this laptop than about the gateway. Treat them as a floor, not a limit.
* Not measured: large bodies, TLS, HTTP/2, Coraza side-car on, many gateway workers, long runs, memory growth.

## Multi-worker (`proxy.workers` in waf.toml, or `WAFGW_WORKERS=N`)

Same machine, a trivial one-process upstream (4000 req/s alone), three load generators of 16 connections each
(`python -m traffic.loadtest`, raw sockets), random client IPs, monitor mode, 8 s runs. Generators, upstream and gateway share
the 8 cores, so these are floors.

| gateway workers | total req/s | p50 | p99 |
|---|---|---|---|
| 1 | 234 | 160 ms | 0.8 s |
| 4 | 719 | 47 ms | 0.35 s |
| 6 | 913 | 29 ms | 0.37 s |

About 4x with 6 workers. Each worker is its own process with its own engine; they share the SQLite database, and re-read bans,
mode, threshold, routes and exemptions from it every 2 s. A ban or a setting change reaches every worker within about 2 s.

**What is NOT shared between workers (the cost of this design):** rate-limit buckets, per-client behavior windows, the bot
detector's history and the stateful rules. The kernel spreads *new connections* over workers, so one client's requests can land
on several. Keep-alive clients stay on one worker, which hides it; a client opening a new connection per request is seen as N
partial clients: its rate limit becomes up to N times looser and burst / URL-walking detection gets less sensitive.
The console's bot table (`/api/bots`) is read from the main process, which handles no traffic, so it is empty with more than one worker.
Fixing that needs shared state (Redis) or routing by client IP; with one worker (the default) nothing changes.

## Measurement mistakes found on the way (kept so nobody repeats them)

* `httpx` as the load generator tops out near 350 req/s even against a trivial upstream, so the first table above measured
  the generator. `traffic/loadtest.py` now uses bare asyncio sockets (4000 req/s against the same upstream).
* A uvicorn server started with several workers (or any pre-bound shared socket) answered every request 40 ms late
  (Nagle + delayed ACK). The gateway sets `TCP_NODELAY` on its worker sockets for that reason.
* Stop a background gateway with SIGTERM: background shell jobs ignore SIGINT, and a leftover process on the same port
  (SO_REUSEPORT lets several share it) silently takes part of the traffic.

## Found and fixed while measuring

Per-request work in the behavior features and the bot detector looped over a client's whole 60 s history, so one busy IP
(a NAT, an office, an attacker) made every request slower. Histories are now capped at 500 requests per client
(`wafgw/engine.py`, `wafgw/bot.py`). The loops are still linear in that cap; incremental counters would remove them.

## Next steps toward real throughput

1. Shared state across workers (Redis, or routing a client to one worker) so rate limits and behavior windows are exact.
2. `uvloop` + `httptools` are now installed and used automatically (set `WAFGW_NO_UVLOOP=1` to turn the loop off). Measured as gateway CPU
   time per request on a busy laptop (A/B, two runs each): 5.9 ms with uvloop vs 6.3 ms without, about 7%. Not the big win hoped for:
   the time goes into Python code per request (Starlette, httpx to the upstream, detection about 0.7 ms, logging), not into the event loop.
   Next: replace httpx with a leaner upstream client, and trim per-request allocations.
3. Consider moving the data plane to a compiled proxy (Go or Rust) and keeping Python only for scoring.
