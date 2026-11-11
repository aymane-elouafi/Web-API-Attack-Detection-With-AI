# Web API Attack Detection

AI-assisted detection of attacks against a web API: classic rules + machine learning,
combined into one risk score. (AI module project.)

## Roadmap

1. **Foundation** (done): vulnerable demo API + labeled traffic generator
2. **Rules-based detector** (done): our own WAF-style rules, plus **Coraza + OWASP CRS** as the industry baseline (done)
3. AI: supervised payload classifier (done); unsupervised behavior model (done, see below)
4. Score fusion + evaluation (rules vs AI vs hybrid)
5. Management interface (dashboard) -- first version done, see below

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
dashboard/            read-only management dashboard (FastAPI + one HTML page)
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

## Dashboard (Phase 5)

Read-only, local, vanilla JS (no external libraries), light and dark, works at phone width,
respects reduced motion / transparency / contrast. It reads `data/` only and never talks to the
demo API.

```bash
.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8100   # then open http://127.0.0.1:8100
```

- **Overview:** every detector side by side, recall by attack type. The threshold slider in the
  top bar re-decides the hybrid live (lower = more alerts, more false alarms).
- **Alerts:** flagged / missed attacks / false alarms, with the reason (which detectors fired,
  rule and Coraza ids).
- **Clients:** ranked by riskiest request; click one for its request timeline (risk, which
  detectors flagged each request, why).
- **Live feed:** Play/Pause replays the dataset in time order (1x / 4x / 20x), colouring rows by risk.

Not built: real live traffic, user accounts, editing rules.

## Attacks covered

SQL injection, XSS (stored), path traversal, mass assignment, BOLA/IDOR,
brute force / credential stuffing.

## Safety

The demo API is vulnerable on purpose. It only uses an in-memory database and a
fake file system, and must only be bound to 127.0.0.1. Never deploy it.
