# wafgw: the WAF gateway

A reverse proxy that puts the detectors (own rules, payload ML, behavior ML) in front of any
HTTP application. Every request is scored 0-1 (same noisy-OR fusion as `detection/fusion.py`),
then allowed, logged as `would_block` (monitor mode) or answered with 403 (block mode).

```
client -> [wafgw proxy :8080] -> your application (upstream)
                |  SQLite event log (data/waf.db)
admin API :9000 (bearer token)  <- dashboard / scripts
```

## Run

```bash
.venv/bin/python -m wafgw.train                       # once: trains models/payload.joblib + behavior.joblib
.venv/bin/uvicorn target_api.app:app --port 8000 &    # the demo application
WAF_ADMIN_TOKEN=change-me .venv/bin/python -m wafgw   # proxy :8080, admin 127.0.0.1:9000, config: waf.toml
```

Docker: `WAF_ADMIN_TOKEN=change-me docker compose up --build` (see `docker-compose.yml`).
Without `WAF_ADMIN_TOKEN` the admin API is not started (the proxy still runs). Without trained
models the gateway runs with rules only and says so at start-up.
Start in `monitor`, watch the events, then `POST /api/mode {"mode":"block"}`.

**TLS** (optional, terminated on the proxy port): put PEM paths in `waf.toml`
(`[tls] cert = "/etc/ssl/site.pem"`, `key = "/etc/ssl/site.key"`); both or neither, the files must exist.
The gateway then serves `https://` and the upstream hop stays plain HTTP (or whatever `upstream` says).
Self-signed test certificate: `openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 30 -subj /CN=localhost`.

## Demo traffic: `traffic.replay`

`traffic.generate` fires its requests in a few seconds, which makes the behavior detector and the rate rule
see unrealistic bursts. `traffic.replay` replays `data/dataset.csv` (read-only, it never rewrites it) through
the gateway with realistic pacing: each session keeps its own gaps between requests (a shopper clicks every few
seconds, a brute-force tool every 0.2 s, divided by `--speed`); only the start of each session is shuffled so
that the whole replay averages `--rate` requests per second. Logins are done live, so tokens are valid.

```bash
WAFGW_TRUST_FORWARDED=1 WAF_ADMIN_TOKEN=change-me .venv/bin/python -m wafgw      # the gateway must read each client's IP
.venv/bin/python -m traffic.replay --url http://127.0.0.1:8080 --rate 6 --seed 1 --report   # ~10 min, then a summary
#   --speed 3     three times faster clicks      --loop   repeat forever (Ctrl-C)      --report [DB]  compare decisions with labels
```

## Behaviour

- Adds `X-Forwarded-For/Proto/Host` and `X-WAF-Request-Id` (also on responses and on the block page); strips hop-by-hop headers;
  streams responses; 413 over `max_body_bytes`; 502/504 on upstream failure.
- Client IP is the TCP peer; `trust_forwarded = true` takes `X-Forwarded-For` (only behind your own load balancer).
- Engine crash: `fail_open` (default, forward) or `fail_closed` (503). Logged as detector `engine`.
- Order of checks: route disabled -> allow list -> deny list (403) -> rate limit (429) -> detectors.
- Per-route overrides in `waf.toml` (`[[routes]]` prefix, mode, threshold, disabled).
- Request limits: invalid `Content-Length` -> 400; body over `max_body_bytes` -> 413; a client that sends its body slower
  than `body_timeout_s` (default 30) -> 408 (slow-body attacks). Keep-alive idle timeout is 5 s.
- WebSockets are refused on purpose (501 for an `Upgrade: websocket` request, handshake rejected on the socket): proxying
  a stream would bypass inspection. Route `/ws` straight to the application in front of the gateway if you need it.
- Hot reload: `models/*.joblib` and `schema.json` are re-checked every 5 s (and by `POST /api/reload`); a new or changed
  file is loaded without a restart, a broken one is reported (`reload_errors` in `/api/health`) and the old model keeps
  running. Per-client behavior windows survive a model swap. Mode, threshold, routes and exemptions are re-read from the
  store by `POST /api/reload`; `waf.toml` itself still needs a restart.
- Passwords/tokens/keys are redacted in logged query and body; the body snippet is cut at 2 KB.
- The behavior model identifies a "session" by a hash of the Authorization/Cookie header (never stored).

## Event schema (table `events`, the contract for the dashboard)

| column | type | meaning |
|---|---|---|
| id | integer | autoincrement |
| ts | real | unix time |
| request_id | text | also sent as `X-WAF-Request-Id` |
| client_ip, method, host, path, query, user_agent | text | the request (query redacted) |
| body_snippet | text | redacted, max 2 KB |
| upstream_status | integer | status the client received (upstream's, or 403/429/413/502/503/504) |
| action | text | `allowed` / `blocked` / `would_block` (monitor mode: attack-level risk, still forwarded) |
| risk | real | fused 0-1; `>= threshold` means attack |
| detectors | text (JSON) | `{"rules": 0.5, "payload ML": 0.98, "behavior": 0.0}` strengths 0-1 (only those > 0; `deny_list`, `rate_limit` appear as 1) |
| reasons | text (JSON) | `[{"detector","score","strength","detail"}]`, `detail` = matched rule ids / behavior features |
| latency_ms | real | time spent in the engine for this request (the added latency) |
| route | text | matching route prefix or `""` |

Tables `lists(ip, kind allow|deny, note, created)` and `settings(key, value JSON)` (`mode`, `threshold`).

## Admin API (`Authorization: Bearer $WAF_ADMIN_TOKEN`, JSON)

| call | |
|---|---|
| `GET /api/health` | no auth. `{status, uptime_s, models:{payload,behavior,schema}, reload_errors}` |
| `POST /api/reload` | re-read changed model files and the stored policy now: `{reloaded:[...], errors:{file:msg}, mode, threshold}` |
| `GET /api/stats?since=3600` | `{window_s, total, avg_risk, by_action, latency_ms:{p50,p95,max}, top_ips, top_paths, timeline[{t,requests,flagged}], mode, threshold}` |
| `GET /api/events` | filters: `since` (unix ts), `action`, `ip`, `path` (substring), `min_risk`, `before_id` (paging), `limit` (<=1000). Newest first, `detectors`/`reasons` already parsed |
| `GET /api/mode`, `POST /api/mode` | `{"mode":"monitor\|block","threshold":0.5}` (either key optional); persisted |
| `GET /api/lists`, `POST /api/lists` | `{"ip":"1.2.3.4 or 10.0.0.0/8","kind":"allow\|deny","note":""}` |
| `DELETE /api/lists/{ip}` | write a CIDR with `_` instead of `/` (`10.0.0.0_8`) |

Errors: 401 bad token, 400 bad input `{"error": ...}`.

## Additions for the console (`dashboard/`)

Tables: `exemptions(id, prefix, param, detector, note, created)`, `feedback(event_id, verdict benign|attack, note, ts)`,
`audit(id, ts, actor, action, detail)`. Every mutating admin call is written to `audit` (actor from the `X-Actor` header).

| call | |
|---|---|
| `GET /api/events/{id}` | one event, plus its `feedback` |
| `GET/POST /api/feedback` | `{"event_id":1,"verdict":"benign\|attack","note":""}` |
| `GET/POST /api/exemptions`, `DELETE /api/exemptions/{id}` | `{"prefix":"/search","param":"q","detector":"rules\|payload ML\|behavior","note":""}` |
| `GET/POST /api/routes` | `{"routes":[{"prefix":"/admin","mode":"block","threshold":0.4,"disabled":false}]}`; persisted, replaces `waf.toml` routes |
| `GET /api/audit?limit=200` | change history |
| `GET/POST /api/settings/alerts` | webhook settings JSON (`enabled, kind slack\|discord\|generic, url, min_risk, dedup_s`) |
| `GET/POST /api/policy` | whole policy as JSON (`version 1`: mode, threshold, routes, lists, exemptions, alerts). POST validates everything first, then replaces |

An **exemption** silences one detector (strength 0, logged as `exempt (was 0.62) ...`) for requests whose path starts with
`prefix` and, if `param` is set, that query parameter / top-level JSON key is present. It never touches the deny list or the
rate limiter. Shared logic (fusion, exemption matching, replay of stored events under a candidate policy) lives in
`wafgw/policy.py`, so the engine, the console and the simulator agree.

## Schema detector (5th detector, `schema`)

Positive security: flags requests that do not fit the API (unknown endpoint / parameter / method, missing required
field, wrong type, value outside a closed set, odd characters or length, privileged fields such as `role`). Code and
policy: `detection/schema.py` (strengths fixed in advance: hard breaks 0.5-0.6, soft signals 0.3-0.45, noisy-OR, 0.5 = alert).

```bash
.venv/bin/python -m wafgw.schema_learn --openapi http://127.0.0.1:8000/openapi.json   # from a spec, no traffic needed
.venv/bin/python -m wafgw.schema_learn --events data/waf.db                          # from allowed gateway events (clean window!)
.venv/bin/python -m wafgw.schema_learn --dataset data/dataset.csv                    # from labeled normal rows
# any combination: learned endpoints fill in, the spec wins on the endpoints it defines. Writes models/schema.json; the running gateway loads it within 5 s (or `POST /api/reload`).
```

Without `models/schema.json` the detector is skipped. Per-route switch: `[[routes]] prefix = "/x"`, `schema = false`. Reasons look like
`{"detector": "schema", "strength": 0.76, "detail": "privileged_field: 'role' is not a known field of PUT /users/me; ..."}`.
Exemptions can silence `schema` like any detector. `GET /api/schema` (admin): `{loaded, findings_24h:{kind: count}, endpoints:[...]}`;
`/api/health` models now include `schema`. Learning guard: a field, value or character needs 5+ sightings and 0.5% of the
endpoint's requests; the learning window must still be clean (attacks repeated 5+ times look normal).

## Known limits

Single process (detectors run in the event loop: about 0.3 ms added per request for repeated
requests, about 5 ms for new text, because the payload model runs through scikit-learn); all behavior state is in
memory and is lost on restart; TLS is terminated on the proxy port only (no certificate renewal, no SNI per site);
no WebSocket proxying (refused with 501); uvicorn has no header-read timeout, so put a load balancer or nginx in front
for protection against slow-header (slowloris) clients; the event log is not rotated.
