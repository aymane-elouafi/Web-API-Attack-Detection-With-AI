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

Docker: `cp .env.example .env`, set `WAF_ADMIN_TOKEN`, then `docker compose up --build -d` (see `docker-compose.yml` and `docs/DEPLOYMENT.md`).
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

## Response protection (`response`) and honeypots

**Leaks.** The gateway reads the application's text/JSON answers (first `max_inspect_bytes`, default 64 KB, before any byte is
sent; larger or binary bodies keep streaming untouched) and looks for: stack traces (Python/Java/PHP/.NET/Node), SQL/DB errors,
private keys, AWS keys, JWTs, `password`/`secret`/`api_key` fields, Luhn-valid card numbers, SSNs, valid IBANs, 5+ distinct
e-mail addresses, directory listings, debug banners, and a response far bigger than the route's running median
(`size_anomaly`, needs 20 samples). Strengths are fixed policy (0.4-1.0), combined by noisy-OR into one `response` reason.
A finding never changes the request-side `risk`, `detectors` or `action`.

| `[response] action` | effect (block mode) | in monitor mode |
|---|---|---|
| `alert` (default) | logged only | logged only |
| `redact` | secrets, cards, keys, IBANs replaced by `[redacted]` (JSON shape kept; stack traces/SQL errors cannot be redacted, they stay alerts) | logged only, traffic untouched |
| `block` | answer replaced by `502 response blocked` when the combined strength >= 0.5 (event `action = blocked`) | logged only |

The gateway asks the application for an uncompressed answer (`Accept-Encoding: identity`) so there is something readable to scan.
Cost: ~0.02 ms for a 100-byte answer, ~0.3 ms for 2 KB, ~15 ms for 64 KB of JSON, worst case (adversarial text) ~50 ms; the
scan runs in the event loop, so lower `max_inspect_bytes` on very busy sites.

**Honeypots and canaries.** `[honeypots] paths` (default `/admin.bak /.env /.git/config /wp-login.php /phpmyadmin /api/internal
/backup.sql`) are answered by the gateway itself with believable fakes and never reach the application. A hit is logged with
`risk 0.95`, reason `honeypot`, `action blocked`. In block mode the client IP is also put on the deny list for `ban_minutes`
(default 30, 0 = never; allow-listed IPs are never banned; monitor mode never bans). The fakes carry **canary credentials**
(an AWS-style key, an API key, a password) derived from a per-installation seed kept in the store. If one comes back in a
request (Authorization header, cookie, query or body) the event gets reason `canary_used`, `risk 1.0`, and the request is
blocked in block mode (would_block in monitor mode) and the IP banned. The canary values are never written to the log.

Event columns added (additive migration of existing databases): `response_flags` (JSON list `{kind, detail, strength}`),
`resp_bytes`; `lists.expires` (unix time, `null` = permanent; expired bans are dropped on lookup). `GET /api/stats` gains `leaks`.
`GET /api/events` accepts `traps=1` internally via the store (`events(traps=True)`: leaks, honeypot and canary events only).

| call | |
|---|---|
| `GET /api/leaks` | last 24 h: `{settings, kinds:{kind:n}, leaks, honeypot_hits, canary_hits, recent_leaks[], recent_hits[]}` |
| `POST /api/leaks/settings` | `{"response":{"enabled":true,"action":"alert\|redact\|block"},"honeypots":{"enabled":true,"canary":true,"ban_minutes":30}}`; stored, active within a second; honeypot paths stay in `waf.toml` |

Console: page **Honeypots & Leaks** (counts, settings, recent leaks and trap hits), `leak` / `honeypot` / `canary used` chips in Events,
and a "Leaks and traps" section in the event drawer.

## Known limits

Single process (detectors run in the event loop: about 0.3 ms added per request for repeated
requests, about 5 ms for new text, because the payload model runs through scikit-learn); all behavior state is in
memory and is lost on restart; TLS is terminated on the proxy port only (no certificate renewal, no SNI per site);
no WebSocket proxying (refused with 501); uvicorn has no header-read timeout, so put a load balancer or nginx in front
for protection against slow-header (slowloris) clients; the event log is not rotated.

## Bots, adaptive rate limit and threat intel

Two more detectors feed the same noisy-OR fusion (strength 0.5 = would alert alone). They need no model
files and are on by default (`[bot] enabled`, `[intel] enabled` in `waf.toml`).

**`bot`** (`wafgw/bot.py`) - is the client a machine, and a hostile one? Never decided by the User-Agent
alone. Findings carry a plain-language reason (`kind: detail`, joined by `; `):

| finding | strength | when |
|---|---|---|
| attack tool | 0.6 | User-Agent names a scanner (sqlmap, nikto, nuclei, wfuzz, gobuster, hydra, ...) |
| automation client / no user agent | 0.15 | curl, python-requests, Go-http-client, ...; empty UA (legitimate scripts exist) |
| fake browser | 0.1-0.2 | a browser UA that sends no `Accept` / `Accept-Language` header (needs the proxy headers) |
| old protocol | 0.1 | HTTP/1.0 |
| machine timing | 0.35 | >= 10 requests in 60 s at a steady <= 5 s rhythm (gap variation < 20%) |
| burst | 0.3 / 0.5 | >= 5 / >= 15 requests per second |
| URL walking | 0.5 | >= 8 different URLs, >= 50% of them 404 |
| credential guessing | 0.5 | >= 80% of the last >= 10 requests refused with 401/403 |
| failing sweep | 0.4 | >= 80% of the last >= 10 requests failed (other 4xx/5xx) |
| no session | 0.2 | >= 20 requests in 60 s without any cookie or token |

Rhythm findings use the answers the application gave (`Engine.observe`). Strengths are a stated policy, not
tuned on test labels (one split, credential guessing vs failing sweep, was made after a first run showed
brute force at 0.4; see the numbers below).

**Adaptive rate limit** (`[rate_limit]`, off by default): the token bucket per client now shrinks with the
client's recent risk (EWMA of its fused risk): rate x (1 - 0.85 x risk), burst likewise, never below 2.
`adaptive = false` restores the fixed limit. A route may override: `[[routes]] prefix = "/login"`,
`rate_per_s = 1`, `burst = 5`.

**`intel`** (`wafgw/intel.py`) - IP reputation from local files you provide (nothing is downloaded):
`<dir>/*.block.txt` (blocklist: IP or CIDR per line, `#`/`;` comments, `1.2.3.0/24 ; SBL123` Spamhaus DROP and
FireHOL netsets work as they are), `<dir>/*.allow.txt` (these clients skip inspection) and `<dir>/networks.csv`
(`cidr,country,asn[,org]`, header optional) which `country_deny = ["KP"]` / `asn_deny = [64500]` use. Default
dir `data/intel/`; tiny examples are in `wafgw/samples/`. Blocklist hit 0.8, country/ASN rule 0.6, DNSBL hit
0.7. Lookups are longest-prefix matches in <= 33 dict lookups, so 100k-entry lists cost microseconds. Files are
re-read when their modification time changes (every ~5 s check) and on `POST /api/reload`. Optional DNSBL
(`dnsbl_enabled = true`, `dnsbl_zones = ["zen.spamhaus.org"]`) runs in background threads with a 1 h cache: the
first request from an unknown IP is never delayed (it simply counts as clean).

```toml
[intel]
enabled = true
dir = "data/intel"
country_deny = []        # ISO codes, needs networks.csv
asn_deny = []
dnsbl_enabled = false
dnsbl_zones = []
[bot]
enabled = true
```

Admin API additions (all need the bearer token):

| endpoint | purpose |
|---|---|
| `GET /api/bots?min_strength=0.25` | clients the bot detector fired on (24 h): requests, strength, finding counts, `gaps` (rhythm) |
| `GET /api/intel` | loaded files (entries, skipped lines, mtime), country/ASN rules, counts, `hits_24h`, `top_hits` |
| `POST /api/intel/import` `{kind: blocklist\|allowlist\|networks, name, text}` | validate and save a list (10 MB max, atomic write), reload |
| `GET /api/intel/export?kind=&name=` | the list as text |
| `DELETE /api/intel/{kind}/{name}` | remove a list file |
| `GET /api/intel/lookup?ip=` | what is known about one IP and why it scores |
| `GET/POST /api/intel/policy` `{country_deny, asn_deny}` | runtime country/ASN rules (persisted in `settings`) |

Events add reasons with detector `bot` or `intel` (`intel_allow` for allowlisted clients); both can be silenced by an
exemption like any detector. The proxy now passes `headers` (raw, ordered) and `http_version` to the engine.

Offline check of the bot detector on the dataset (UA + rhythm only, the dataset has no other headers):
`python -m wafgw.eval_bot`.

## Coraza + OWASP CRS as a detector (`coraza`)

Optional. A Coraza side-car (`waf/`, started with `INSPECT_ONLY=1`) answers `204` with its verdict headers
(`X-WAF-Score`, `X-WAF-Rules`) and never touches the application. The gateway sends it a copy of each request
BEFORE deciding, and fuses the verdict like any detector: strength = `min(score / 10, 1)` (CRS score 5 = alert),
rule ids in the reason detail, exemptions can silence it. Enable with `[coraza] enabled = true` / `url` in
`waf.toml` or `WAFGW_CORAZA_URL=http://coraza:8081` (also enables it). If the side-car is down or slower than
`timeout_s`, the request is still judged by the other detectors and the reason says `coraza unavailable`.
Cost measured in Docker: about +4 ms p50. Why not "gateway -> Coraza -> application" (chain)? In that layout the
verdict only exists in the application's RESPONSE, after the application has already run the request, so block
mode could not stop anything.

Note: CRS rule 920350 ("Host header is a numeric IP") adds a little to every request reached by IP address;
use a real host name in front of the gateway.

## Incidents, AI explainer and reports

**Incidents** (`wafgw/incidents.py`, no LLM needed). Flagged events from one client are grouped into an incident
(a quiet gap of 300 s ends it). Each incident is classified from what fired (rule ids, schema finding kinds, behavior
features, payload-ML text) and written up deterministically: what happened, which detectors agreed (confidence),
severity (worst technique x risk, plus whether the application answered 2xx, volume and breadth), the impact
(`blocked | failed | possibly_succeeded | unknown`, from `upstream_status`, and a login that works after 5+ failures),
references (OWASP API Security Top 10, OWASP Top 10 2021, CWE, MITRE ATT&CK), fix guidance and one-click actions
(`ban`, `block_mode`, `review_event`). Identical consecutive requests collapse into one timeline step.

| Endpoint | |
|---|---|
| `GET /api/incidents?since=&until=&gap=&limit=` | most severe first, without timeline/narrative |
| `GET /api/incidents/{id}` | full story; `id` is the first event id of the incident |
| `POST /api/incidents/{id}/narrative` | LLM paragraph; **403 unless `[explainer]` is enabled**, 502 if the endpoint fails |
| `GET /api/explainer` | `{enabled, model, format, sends_ip, endpoint_host}` (never the key) |
| `GET /api/report?since=&until=` or `window_h=` | the JSON report |
| `GET /api/reports` / `POST /api/reports` | list saved files + schedule / build and save one now (webhook if `reports.webhook`) |
| `GET /api/reports/{name}` | one saved `.html` / `.json` (names are validated) |

**LLM explainer** (`wafgw/explainer.py`) is OFF by default and never required. With `[explainer] enabled = true` plus
`url`, `model` (and `api_key_env`, the NAME of the env var holding the key) any OpenAI- or Anthropic-compatible
endpoint (for example a local gateway such as OmniRoute) gets only the computed facts: technique names, counts,
outcome, the order of events, path shapes. Never sent: request bodies, headers, query strings, free-text evidence, or
the full client IP (last octet masked unless `send_ip = true`). The console labels the result "AI-written".

**Reports** (`wafgw/report.py`): executive summary, traffic, top paths/clients, attack types with references, notable
incidents with timelines, false-positive review (events you marked benign), detector agreement matrix (and what each
detector caught alone), recommendations. The HTML is self-contained with print CSS (browser Print > Save as PDF).
`[reports] enabled = true` writes `data/reports/YYYY-MM-DD_HHMM.html` + `.json` every `every_h` hours and can send a
summary to the Alerts webhook. At most the newest 20,000 flagged events are analysed per report (the page says so).

The console adds **Incidents** and **Reports** pages (`dashboard/static/incidents.js`) and two routes:
`/api/report-html?window_h=24[&download=1]` renders the report from the gateway's JSON, `/api/report-file/{name}`
serves a saved one.
