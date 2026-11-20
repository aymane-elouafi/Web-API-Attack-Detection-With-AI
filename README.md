# Web API Attack Detection

AI-assisted detection of attacks against a web API: classic rules + machine learning,
combined into one risk score. (AI module project.)

## Roadmap

1. **Foundation** (done): vulnerable demo API + labeled traffic generator
2. **Rules-based detector** (done): our own WAF-style rules, plus **Coraza + OWASP CRS** as the industry baseline (done)
3. AI: supervised payload classifier (done); unsupervised behavior model (done, see below)
4. Score fusion + evaluation (rules vs AI vs hybrid)
5. Management interface (console) -- done, see below
6. **Real reverse-proxy WAF gateway** (`wafgw/`) and training on real datasets -- done, see below

## Layout

```
common/seed.py        shared seed data (users, products, orders)
target_api/app.py     intentionally vulnerable FastAPI app (local only, fake data)
traffic/payloads.py   attack payload catalogue (with evasion variants)
traffic/generate.py   simulates users + attackers, writes data/dataset.csv
detection/rules.py    rules detector: signature rules + rate/login-failure rules, CRS-style scoring
detection/metrics.py  precision / recall / false-positive rate, shared by all detectors
detection/run_rules.py  runs the rules on the dataset and prints a report
detection/run_waf.py  evaluates Coraza+CRS and compares it with our rules
detection/report.py   report printing shared by all detectors
detection/ml_payload.py  supervised payload classifier (features + model + grouped cross-validation)
detection/run_ml.py   evaluates it and compares it with the rules and Coraza
wafgw/                reverse-proxy WAF gateway (rules + 2 AI models + fusion, block/monitor, event log, admin API)
dashboard/            management console (FastAPI + vanilla-JS single page) and the old evaluation view
detection/external_data.py  loaders/dedupe for real datasets (FWAF, CSIC 2010, payload corpora)
detection/run_external.py   trains/evaluates on them with CSIC 2010 held out
detection/ml_behavior.py  unsupervised behavior model (rolling per-client features + Isolation Forest)
detection/run_behavior.py  evaluates it and compares it with every other detector
detection/run_novel.py  held-out test on attack payloads that are not in the generator's catalogue
waf/                  Coraza + OWASP CRS inspection proxy (Go, built and run in Docker)
tests/                unit tests for the rules
data/                 generated datasets and predictions
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

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

## Run the rules detector

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
their recall on injection attacks is optimistic. Phase 4 will test on held-out,
novel payloads.

## Coraza + OWASP CRS baseline

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

## Payload classifier (AI model #1)

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

## Behavior model (AI model #2)

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

## Fusion and final evaluation (Phase 4)

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
**Evaluation** (the dataset comparison of all detectors). Known issue: the demo generator sends
requests in seconds, so the behavior detector flags ~55% of the demo traffic; a paced replay
would fix the demo, not the detectors.

## Training on real datasets

Downloaded to `data/external/` (git-ignored; sources, sizes and licence notes in
`data/external/SOURCES.md`): FWAF, CSIC 2010 (held out, never trained on), PayloadsAllTheThings,
SecLists Fuzzing, OWASP CRS regression tests. `detection/external_data.py` normalises, dedupes
across sources before any split and makes attack and benign text the same shape; headers are
never used. `.venv/bin/python -m detection.run_external` evaluates.

Held-out CSIC 2010 (25k requests, threshold 0.5): old model AUC 0.64 / recall 19% / false alarms
0.2%; trained on everything AUC 0.63 / recall 21% / 0.1%; own rules recall 15%. Recall is low for
every detector because ~13.5k of the 15.4k CSIC anomalies are structural (renamed parameters,
extra path segments), not payload text. On the ~3k classifiable payload requests the models catch
95-100%. Catching the structural ones needs a schema / unknown-parameter check (API security), the
next feature. Leakage: a shape-only model scored AUC 0.93 inside training but 0.57 on CSIC, so
the in-training cross-validation (AUC 0.99) is inflated; quote CSIC only. Weak spot: held-out
harmless text with heavy punctuation is still flagged too often (17-49% on two small sets).

## API schema detection (5th detector)

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

## Attacks covered

SQL injection, XSS (stored), path traversal, mass assignment, BOLA/IDOR,
brute force / credential stuffing.

## Safety

The demo API is vulnerable on purpose. It only uses an in-memory database and a
fake file system, and must only be bound to 127.0.0.1. Never deploy it.

## Contributors

- [Aymane Elouafi](https://github.com/aymane-elouafi) -- project owner
- Claude (Anthropic) -- AI pair programmer; co-author of the commits
