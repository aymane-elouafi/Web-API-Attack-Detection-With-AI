# Web API Attack Detection

A web application firewall (WAF) you can put in front of a web API, built around one idea: **no single
detector is enough, so several are fused into one explainable risk score.** Own signature rules and
OWASP CRS (via Coraza) catch known payloads, a payload classifier and a behavior model (both machine
learning) catch disguised and behavioral attacks, and an API schema detector catches structural
anomalies. The result runs as a reverse proxy (`wafgw/`) with a management console (`dashboard/`).
(AI module project.)

## Architecture

```
client -> wafgw proxy -> [lists, rate limit] -> 5 detectors -> noisy-OR fusion -> allow / 403 -> your app
                                                    |                |
                                  rules, payload ML, behavior ML,    +--> SQLite event log -> admin API -> console
                                  schema, exemptions
```

Diagram and a table of what each detector catches: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Gateway API and event schema: [`wafgw/README.md`](wafgw/README.md).

## Quick start

```bash
python3 -m venv .venv                       # Python 3.11+
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -t .      # needs no models and no downloaded data

# 1) protect the demo API with the gateway (monitor mode first)
.venv/bin/python -m wafgw.train                           # trains models/payload.joblib + behavior.joblib
.venv/bin/uvicorn target_api.app:app --port 8000 &        # the demo application (vulnerable on purpose, localhost only)
WAF_ADMIN_TOKEN=change-me .venv/bin/python -m wafgw       # proxy :8080 -> :8000, admin API 127.0.0.1:9000

# 2) the console (second terminal)
WAF_ADMIN_TOKEN=change-me .venv/bin/python -m dashboard   # http://127.0.0.1:8100
```

Docker: `WAF_ADMIN_TOKEN=change-me docker compose up --build` (not built or tested yet). Without
`data/external/` the models are trained on the synthetic demo dataset only; with it, on real data
(see "Training on real datasets"). Details of each piece are below.

## Results at a glance

All numbers come from the sections below, with their caveats. Detection quality depends heavily on
the data: the demo dataset is synthetic, CSIC 2010 is one synthetic shop, the novel sets are small.

| Test | rules | Coraza + CRS | payload ML | behavior ML | schema | hybrid |
|---|---|---|---|---|---|---|
| Demo dataset: recall (3,732 requests, 1,092 attacks) | 64.7% | 39.1% | 44.3% | 17.0% | - | **84.5%** (1 false alarm) |
| Held-out CSIC 2010: recall / false alarms (25k requests) | 14.9% / 0.0% | not run | 20.3% / 0.2% | - | 82.5% / 0.1% | rules+payload+schema 86.7% / 0.3% |
| Novel payloads (30 attacks, 15 look-alikes) | 22/30, 0 FP | 30/30, 1 FP (earlier run) | 29/30, 1 FP (real-data model); 28/30, 0 FP (demo model) | - | - | - |
| Blind harmless text (200 sentences x 3 shapes): false-alarm rate | 1.0% | not run | 5.5% (was 51.5%) | - | - | - |


## The detectors


### Rules detector (own WAF-style rules)

```bash
.venv/bin/python -m detection.run_rules          # report on data/dataset.csv
.venv/bin/python -m unittest discover -s tests -t .   # unit tests
```

Each request gets an anomaly score (every matching rule adds points); a score of
5 or more is flagged. Baseline result on the default dataset (seed 42):
precision 100%, recall 64.7%, false-positive rate 0%. It catches injection, XSS, most
path traversal and most brute force, but misses every BOLA and mass-assignment request --
the cases that need context or behavior, which is what the AI phases target.

Caveat: the rules were written by the same author as the payload generator, so
their recall on injection attacks is optimistic (see the held-out tests below).

### Coraza + OWASP CRS baseline

[Coraza](https://coraza.io) is an open-source, ModSecurity-compatible WAF written in Go. `waf/`
is a small reverse proxy that runs every request through Coraza with the real OWASP Core Rule
Set (CRS v4, paranoia level 1, anomaly threshold 5). It runs in **monitor mode**: every request
is still forwarded to the API, and the verdict comes back as response headers
(`X-WAF-Score`, `X-WAF-Rules`, `X-WAF-Block`), which the generator saves as `waf_*` columns.
Go is not needed on the host -- it is compiled inside Docker.

```bash
docker build -t web-api-coraza:local waf/
```

Start the API (terminal 1), then the proxy (terminal 2):

```bash
.venv/bin/uvicorn target_api.app:app --host 127.0.0.1 --port 8000
```

```bash
docker run -d --rm --name coraza-proxy --network host --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges -e LISTEN=127.0.0.1:8080 -e UPSTREAM=http://127.0.0.1:8000 web-api-coraza:local
```

Generate traffic THROUGH the proxy and evaluate (stop it afterwards with `docker stop coraza-proxy`):

```bash
.venv/bin/python -m traffic.generate --seed 42 --url http://127.0.0.1:8080
.venv/bin/python -m detection.run_rules
.venv/bin/python -m detection.run_waf
```

Tuning that was needed (normal when putting CRS in front of a REST API): `PUT/PATCH/DELETE`
are allowed (CRS only allows GET/HEAD/POST/OPTIONS by default), and the generator sends a
real `Host` name (CRS flags bare-IP Host headers). Only request rules are evaluated;
CRS response rules (e.g. SQL-error leakage) are not.

Results on the default dataset (seed 42, 3,732 requests, 1,092 attacks):

| | precision | recall | false alarms |
|---|---|---|---|
| own rules | 100% | 64.7% | 0 |
| Coraza + CRS | 100% | 39.1% | 0 |
| either one flags | 100% | 65.9% | 0 |

Coraza detects 100% of SQL injection, XSS and path traversal (including double-encoded
payloads, where our rules miss some) but nothing behavioral: BOLA, mass assignment and
brute force are invisible to CRS (our rate / failed-login rules catch 92% of brute force).
Both detectors miss every BOLA and mass-assignment request -- the target for the AI phase.

User agents: only ~12% of injection / traversal / brute-force sessions use a noisy tool's
default agent (sqlmap, Nikto, Hydra), and every request in those sessions is labeled an
attack; other attackers use ordinary-looking agents. (With seed 42 only 9 requests, 1% of the
attacks, ended up with a tool agent.) The report also shows each detector without its
user-agent rule (it changes almost nothing). An earlier generator where most
attackers used sqlmap/Nikto agents let that one rule inflate Coraza's brute-force score and
created fake "false alarms", so it was changed. The user agent must not be an ML feature.

### Payload classifier (AI model #1)

Learns from labeled requests instead of hand-written rules: character n-grams of the request
(method, path shape with ids masked, parameter names, decoded values) plus a few numeric
features (length, entropy, odd-character share) into a logistic regression. It never sees the
client IP, user agent, attack type or variant, and it is trained only on payload attacks
(SQLi, XSS, traversal, mass assignment) -- BOLA and brute force are behavior, not text.

```bash
.venv/bin/python -m detection.run_ml      # 5-fold cross-validation grouped by client IP + comparison
.venv/bin/python -m detection.run_novel   # held-out test on novel payloads
```

Same dataset: 100% recall on SQLi, XSS, traversal and mass assignment, 0 false alarms, but that
number is **memorisation**: the generator re-uses ~30 attack strings for training and testing.
The honest number is the held-out test (30 novel attacks, 15 harmless look-alikes; small, so
indicative only): payload ML catches 28/30 (93%) with 0 false alarms; own rules catch 22/30 (73%)
with 0. A first version learned `--` as "attack" and flagged "a -- b" and "great -- would buy
again"; adding ~45 varied harmless sentences (`BENIGN_TEXT` in `traffic/payloads.py`, different
from the test sentences, but written by the same author) to the training data fixed it.

**Hard negatives, second round (real-data model).** Once trained on real data (FWAF, payload lists,
CRS tests) the model flagged about half of punctuation-heavy harmless text, because the benign side
of those datasets has almost no punctuation. `detection/benign_text.py` now generates 12,000 harmless
texts from 38 template families (apostrophes, dashes, quotes, `< >`, `%`, SQL/HTML words in natural
use, code snippets, URLs, e-mails, accents and non-Latin scripts) as extra training rows, split by
template family for validation. Sample weights (x2, x4) did not help and were dropped. Blind test:
`detection/harmless_set.py` holds 200 harmless sentences written by hand after this design was
frozen (no shared templates), each sent in three request shapes (`.venv/bin/python -m detection.run_external`):

| model | false-alarm rate (requests) | sentences flagged in any shape |
|---|---|---|
| previous production model (no hard negatives) | 51.5% | 108/200 |
| with hard negatives (first round) | 16.0% | 35/200 |
| **+ conversational prose templates (now)** | **5.5%** | **14/200** |
| own rules, before tightening SQLI-1/SQLI-6 | 8.5% | 17/200 |
| **own rules (now)** | **1.0%** | **2/200** |

The price: on held-out CSIC 2010 the classifier's recall is 19.8% (was 20.7% before any hard negatives) with 0.2% false
alarms, its recall on the SQLi-looking CSIC requests fell from 94.6% to 78.7%, and the
novel-attack set is unchanged (29/30 caught, 1/15 look-alikes flagged). The second round (prose templates, and rules
SQLI-1/SQLI-6 now needing the shape of a real injection: no more hits on `"a" or "b"` or `'x' -- some words`)
was written after seeing which blind sentences failed, so the 5.5% / 1.0% figures are optimistic: the blind set
is spent. Through the whole gateway (rules + model + schema) the same 600 requests gave 101 false alarms before and 34 after.
Write a fresh blind set before trusting a further improvement; keep monitor mode and exemptions for free-text routes.

### Parser-style token model (added to the payload classifier)

The payload classifier is now two linear models whose probabilities are averaged: character n-grams (what the text
looks like) and token-class n-grams (what it is built from: `' or 1=1 --` becomes `q K:or n = n c` whatever the numbers
or spacing, see `detection/tokens.py`). Same training data, held-out CSIC 2010, 30 novel attacks, 200-sentence harmless set:

| model | CSIC recall | CSIC SQLi | CSIC XSS | CSIC false alarms | novel caught | look-alike false alarms | harmless-set false alarms |
|---|---|---|---|---|---|---|---|
| character n-grams only | 19.8% | 78.7% | 96.0% | 0.22% | 29/30 | 1/15 | 4.3% |
| token classes only | 31.2% | 97.5% | 86.1% | 0.23% | 30/30 | 3/15 | 14.0% |
| **average (shipped)** | **24.4%** | **94.8%** | **93.9%** | **0.09%** | **30/30** | **0/15** | 4.7% |

Putting both feature sets into ONE model was worse than either alone (SQLi 67%): the token columns pulled weight away
from the n-grams. The first tokenizer also had a bug the CSIC misses exposed (a balanced-string rule let one stray
quote swallow the injection after it). The harmless set was already spent when this was measured. Overall CSIC recall
stays low because most CSIC attacks are structural (no attack text): that is the schema detector's job.

### Head-to-head with Coraza + CRS (the BunkerWeb / ModSecurity engine)

Held-out CSIC 2010, same requests for everyone (full table, caveats and how to reproduce: [docs/BENCHMARK.md](docs/BENCHMARK.md)):

| detector | recall | false alarms on normal traffic |
|---|---|---|
| Coraza + CRS, paranoia 1 | 23.1% | 0.0% |
| Coraza + CRS, paranoia 2 | 37.7% | 15.6% |
| Coraza + CRS, paranoia 3 | 78.0% | 71.1% |
| our rules + payload model (no app learning) | 28.5% | 0.1% |
| **ours: rules + payload model + schema** | **87.4%** | **0.3%** |

The schema detector learns the application, which CRS cannot; without it we are only slightly ahead of CRS level 1. SQLi/XSS/traversal: ours 100%, CRS level 1 86% on SQLi.

### Behavior model (AI model #2)

Unsupervised, no labels: for each request it summarises what that client did in the last 60 s
(distinct order ids, share of order requests, errors, error ratio, 404s, failed logins) and an
Isolation Forest scores how unusual that is. It targets what text-based detectors cannot see.

```bash
.venv/bin/python -m detection.run_behavior   # report + comparison with every other detector
```

Ranking quality (AUC, normal vs attack): BOLA 0.99, brute force 0.995. Flagging the 5% most
unusual requests (a policy choice, not tuned on labels): BOLA 50%, brute force 13%, 1 false
alarm. A "shared object" feature (another user already requested this order) raised BOLA from
45%. The alert budget is the only knob; trade-off (BOLA / brute force / false alarms): 5%
50/13/0.0%, 10% 77/42/0.5%, 15% 92/80/1.2%, 20% 97/100/4.7%. Everything together ("any of
them" at 5%): 84.5% recall, 1 false alarm. The first requests of a burst are missed (the
window is still empty).

Improvement history: the first version used 7 generic features (BOLA AUC 0.94, brute force
0.98). Keeping only features that describe the attacks gave 0.99 / 0.995; adding more generic
ones (request count, speed, session age, distinct paths) made it worse. I compared about ten
feature sets using the labels, so these AUCs are slightly optimistic. Caveats: only 8 BOLA and
6 brute-force clients in the data, and the model is fit on the same traffic it scores (normal
for anomaly detection; a live system would train on earlier traffic).

### API schema detection (5th detector)

Positive security: learn what a normal request to each endpoint looks like (allowed methods,
parameters, required fields, types, lengths, character classes) from clean traffic, or import an
OpenAPI file, and flag what does not fit: unknown endpoint/method/parameter, missing required
field, wrong type, length or charset outlier, privileged fields (`role`, `is_admin`, ...). A
parameter counts as normal only if seen >= 5 times and in >= 0.5% of that endpoint's traffic, so a
few attacks in the learning window do not poison it.

```bash
.venv/bin/python -m wafgw.schema_learn --openapi http://127.0.0.1:8000/openapi.json   # or --dataset / --events
.venv/bin/python -m detection.run_schema --openapi http://127.0.0.1:8000/openapi.json
```

Held-out CSIC 2010 (learned on 4.8k normal requests, tested on 4.8k unseen normal + all 15.4k
anomalies): schema alone 82.5% recall / 0.1% false alarms; rules + payload ML + schema 86.7% /
0.3% (before: 23.9% / 0.1%). The 13.5k anomalies with no attack text: 80.5% (payload ML 9.9%). If
the learning window has 5% anomalies mixed in, recall drops to 76.6%; at 20%, 53.7%. Demo API
dataset: mass assignment 100%, 0 false alarms on 1.5k normal requests; the OpenAPI spec alone
flags mass assignment and unknown fields with no learning. BOLA and brute force are not claimed.
Caveats: CSIC is one synthetic shop (schema learning is unusually easy there); rarely visited
pages false-alarm as unknown endpoints; the learning window must be clean. Not done: hot reload of
`schema.json`, repeated-parameter check, exemptions per finding kind.

### Fusion and final evaluation

`detection/fusion.py` turns each detector into an "alert strength" (0.5 = this detector alone
would alert: rules / Coraza score 5 of 10, payload ML p = 0.5, behavior = its alert-budget cutoff)
and combines them with a noisy-OR, `1 - prod(1 - s)`; risk >= 0.5 is flagged. One confident
detector is enough, several half-convinced ones add up. The mappings are a stated policy, not
tuned on labels.

```bash
.venv/bin/python -m detection.run_fusion                                   # needs the four predictions_*.csv
.venv/bin/python -m detection.run_fusion --waf-url http://127.0.0.1:8080   # + Coraza on the novel payloads
```

Default dataset (3,732 requests, 1,092 attacks):

| | precision | recall | false alarms |
|---|---|---|---|
| rules only | 100% | 64.7% | 0 |
| Coraza only | 100% | 39.1% | 0 |
| AI only (payload + behavior) | 99.9% | 62.1% | 1 (0.0%) |
| **hybrid (all four, fused)** | 99.9% | **84.5%** | 1 (0.0%) |

Each detector covers a different gap: Coraza/rules/payload ML the injections, rules the
brute force, payload ML mass assignment, behavior ML the only BOLA hits (50%). The hybrid still
misses 145 BOLA and 24 brute-force requests (the start of each burst). On this data fusion
equals the plain union of the four flags; the noisy-OR only matters when detectors are
half-convinced, which the dataset rarely produces.

Novel-payload test (30 unseen attacks, 15 harmless look-alikes; single requests, so no behavior
model; small, indicative only): own rules 22/30, 0 false alarms; payload ML 28/30, 0; Coraza+CRS
30/30, 1 (Coraza measured earlier, not re-run since the payload fix). Coraza is strongest on unseen injections, the hybrid's value is coverage of
behavior attacks, not payloads.

## Reverse-proxy WAF gateway (`wafgw/`)

The detectors, packaged as a real WAF: it sits in front of your server, inspects every request
(own rules + stateful rate/login rules, payload ML, online behavior model, noisy-OR fusion) and
either forwards it or answers with a clean 403.

```bash
.venv/bin/python -m wafgw.train                      # trains models/payload.joblib + behavior.joblib
WAF_ADMIN_TOKEN=change-me .venv/bin/python -m wafgw  # proxy :8080 -> upstream in waf.toml, admin 127.0.0.1:9000
# or: WAF_ADMIN_TOKEN=... docker compose up --build   (gateway + demo API; image not built/tested yet)
```

Modes: **monitor** (forward everything, log "would block") and **block**; IP allow/deny lists,
per-route overrides, token-bucket rate limit, fail-open/closed policy, scoped exemptions for false
positives, SQLite event log (WAL, background writer, passwords redacted), token-protected admin
API (documented in `wafgw/README.md`, which also holds the event schema). Measured overhead:
about +0.3 ms for repeated requests, +5 ms for new text (the payload model runs).
Not done: TLS termination (put it behind Caddy/nginx or add certs), Coraza chained in,
sharing state between several gateway copies, WebSockets, log rotation.

### Gateway layers beyond the five detectors

- **Response protection** (`wafgw/response.py`, `guard.py`): scans the start (64 KB) of text/JSON
  answers for stack traces, DB errors, private keys, cloud keys, JWTs, password/secret fields,
  Luhn-valid cards, SSNs, IBANs, bulk e-mails, directory listings and abnormal response size;
  action `alert` (default), `redact` or `block` (block mode only). Larger or binary bodies stream.
- **Honeypots and canaries** (`wafgw/honeypot.py`): fake `/.env`, `/.git/config`, `/backup.sql`,
  `/api/internal`, login pages answered by the gateway itself; a hit is a near-certain attacker
  (auto-ban with expiry in block mode). Canary credentials served there raise a risk-1.0
  `canary_used` event if later presented.
- **Bot and reputation layer** (`wafgw/bot.py`, `intel.py`): scanner signatures, fake-browser
  header anomalies, robotic rhythm, failing sweeps; adaptive per-client rate limits; operator
  supplied IP blocklists/allowlists (Spamhaus/FireHOL format) and country/network rules from
  `data/intel/` (nothing is downloaded). 0 of 2,640 normal dataset requests reached the alert
  level; bot signals are meant to add to the other detectors, not replace them.
- **Coraza side-car (optional 6th detector)**: the gateway sends a copy of each request to a
  Coraza+CRS side-car (`INSPECT_ONLY=1`) and fuses its verdict (`docker compose --profile coraza`).
- **Incidents and reports** (`wafgw/incidents.py`, `report.py`, `explainer.py`): events are grouped
  into incidents with a rule-based write-up (timeline, outcome, severity, OWASP API Top 10 / CWE /
  MITRE ATT&CK, fix advice, one-click actions); printable self-contained HTML reports and JSON,
  optionally scheduled; an optional LLM narrative that is OFF by default, sends only computed
  facts (no bodies/headers, masked IP) and is labelled "AI-written".
- **Docker**: `docker compose up -d` runs gateway + demo API + console (non-root, read-only fs,
  admin and console on 127.0.0.1, token required, volumes for the event DB and models). Through
  the gateway requests took ~12-14 ms median (Docker port forwarding included), ~18 ms with
  Coraza. See `docs/DEPLOYMENT.md`; its backup, systemd and nginx/Caddy examples are untested.

Caveats: the demo data is all attacks against a deliberately vulnerable app, so incident
severities cluster high; models in the Docker image are trained on the synthetic data only
(copy your stronger local ones in, see the deployment guide); a fast benchmark loop from one IP
without cookies can itself trip the bot rhythm rules.

## Management console

`python -m dashboard` serves a vanilla-JS single page (no CDN, light/dark, phone width, designed
with the apple-design skill). The gateway token stays on the server.

```bash
WAF_ADMIN_TOKEN=change-me .venv/bin/python -m dashboard                    # http://127.0.0.1:8100, no login, localhost only
CONSOLE_PASSWORD=... WAF_ADMIN_TOKEN=change-me .venv/bin/python -m dashboard   # with a login
```

Pages: **Overview** (trend, top reasons, live feed, monitor/block switch), **Events** (explain
panel: per-detector strengths, rule evidence, the n-grams that drove the ML score, offending text
highlighted; mark benign/attack, exempt, ban), **Learning Inbox** (suggested scoped exemptions with
simulated impact; unsafe ones cannot be approved), **Policies** (mode, threshold, routes, lists,
live preview), **Simulator** (replays stored events + a known-attack corpus; the server refuses a
change that would lose a known attack), **Threats** (per-client timelines), **Alerts**
(Slack/Discord/webhook with dedup), **Settings** (policy export/import as JSON, audit log),
**Evaluation** (the dataset comparison of all detectors), plus **Incidents**, **Reports**, **Honeypots & Leaks** and bot/reputation panels on **Threats**. Known issue: the demo generator sends
requests in seconds, so the behavior detector flags ~55% of the demo traffic; a paced replay
would fix the demo, not the detectors.

## Training on real datasets

Downloaded to `data/external/` (git-ignored; sources, sizes and licence notes in
`data/external/SOURCES.md`): FWAF, CSIC 2010 (held out, never trained on), PayloadsAllTheThings,
SecLists Fuzzing, OWASP CRS regression tests. `detection/external_data.py` normalises, dedupes
across sources before any split and makes attack and benign text the same shape; headers are
never used. `.venv/bin/python -m detection.run_external` evaluates.

Held-out CSIC 2010 (25k requests, threshold 0.5): old model AUC 0.64 / recall 19% / false alarms
0.2%; trained on everything AUC 0.63 / recall 20% / 0.2% (with the 12k hard negatives; 21% / 0.1% without); own rules recall 15%. Recall is low for
every detector because ~13.5k of the 15.4k CSIC anomalies are structural (renamed parameters,
extra path segments), not payload text. On the ~3k classifiable payload requests the models catch
95-100%. Catching the structural ones needs a schema / unknown-parameter check (API security), the
next feature. Leakage: a shape-only model (lengths, slashes, character shares) scored AUC 0.91 inside training
but 0.38 on CSIC, so the in-training leave-family-out cross-validation (AUC 0.99, recall 95.4%, 3.4% false alarms; harmless FWAF lines 0.6%, the 94 hand-made sentences 6.4%, CRS "negative" tests 50.8%) is inflated; quote CSIC only. Weak spot: held-out
harmless text with heavy punctuation is still flagged too often (5.5% on the 200-sentence blind set after two rounds of fixes, now spent; see
the payload classifier section).

## Generate a dataset

Terminal 1 -- start the vulnerable API (restart it between runs for a clean state):

```bash
.venv/bin/uvicorn target_api.app:app --host 127.0.0.1 --port 8000
```

Terminal 2 -- generate traffic:

```bash
.venv/bin/python -m traffic.generate --seed 42
```

Output: `data/dataset.csv` with one row per request: what the server saw
(method, path, query, body, user agent, status, size, time) plus the ground-truth
`label` (0 normal / 1 attack), `attack_type` and evasion `variant`.

## Layout

```
common/seed.py          shared seed data (users, products, orders)
target_api/app.py       intentionally vulnerable FastAPI app (local only, fake data)
traffic/payloads.py     attack payload catalogue (with evasion variants) + harmless text for training
traffic/generate.py     simulates users + attackers, writes data/dataset.csv
detection/rules.py      rules detector: signature rules + rate/login-failure rules, CRS-style scoring
detection/ml_payload.py supervised payload classifier (features + model + grouped cross-validation)
detection/ml_behavior.py unsupervised behavior model (rolling per-client features + Isolation Forest)
detection/schema.py     API schema detector (learned or OpenAPI)
detection/fusion.py     noisy-OR score fusion
detection/external_data.py  loaders/dedupe for real datasets (FWAF, CSIC 2010, payload corpora)
detection/tokens.py                        token-class (parser-style) features
detection/benign_text.py, harmless_set.py  hard-negative generator and the blind harmless test set
detection/run_*.py      evaluation scripts (rules, waf, ml, behavior, novel, fusion, external, schema)
detection/metrics.py, report.py  shared metrics and report printing
wafgw/                  reverse-proxy WAF gateway (engine, proxy, event store, admin API, training)
dashboard/              management console (FastAPI + vanilla-JS single page) and the evaluation view
waf/                    Coraza + OWASP CRS inspection proxy (Go, built and run in Docker)
docs/ARCHITECTURE.md    request-flow diagram and detector coverage table
tests/                  unit tests (no models or downloaded data needed)
data/                   demo dataset and predictions; data/external/ (git-ignored) holds real datasets
.github/workflows/ci.yml  runs the tests on Python 3.11 and 3.12
```

## Roadmap

1. Foundation (done): vulnerable demo API + labeled traffic generator
2. Rules-based detector (done) and the Coraza + OWASP CRS baseline (done)
3. AI: supervised payload classifier and unsupervised behavior model (done)
4. Score fusion + evaluation (done)
5. Management console (done)
6. Reverse-proxy WAF gateway, training on real datasets, API schema detection (done)
7. Next: TLS termination, Coraza chained into the gateway, shared state across gateway copies, response-side leak detection, paced demo replay, a blind set for each further model change.

## Attacks covered

SQL injection, XSS (stored), path traversal, command injection (real-data model only), mass assignment,
BOLA/IDOR, brute force / credential stuffing, structural API anomalies (unknown/renamed parameters, odd paths).

## Safety

The demo API is vulnerable on purpose. It only uses an in-memory database and a
fake file system, and must only be bound to 127.0.0.1. Never deploy it. The gateway admin API
refuses to start without `WAF_ADMIN_TOKEN`; the console has no login unless `CONSOLE_PASSWORD` is set,
so keep it on localhost.

## Contributors

- [Aymane Elouafi](https://github.com/aymane-elouafi) -- project owner
- Claude (Anthropic) -- AI pair programmer; co-author of the commits
