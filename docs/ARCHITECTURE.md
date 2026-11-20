# Architecture

## Request flow

```mermaid
flowchart LR
    C[Client] --> P["wafgw proxy<br/>(reverse proxy :8080)"]
    P --> L{"allow / deny list,<br/>rate limit"}
    L -- denied --> B[403 / 429 page]
    L -- pass --> E["Engine: 5 detectors"]
    subgraph D["Detectors (each returns a 0-1 alert strength)"]
        R["rules<br/>signatures + rate / failed logins"]
        M["payload ML<br/>char n-grams + logistic regression"]
        H["behavior ML<br/>60 s per-client window + Isolation Forest"]
        S["schema<br/>learned or OpenAPI structure"]
        X["exemptions<br/>silence one detector per route/param"]
    end
    E --> D
    D --> F["Fusion: noisy-OR<br/>risk = 1 - prod(1 - strength)"]
    F --> A{"risk >= threshold?"}
    A -- no --> U[Upstream application]
    A -- "yes, block mode" --> B
    A -- "yes, monitor mode" --> U
    U --> P
    F --> V[("Event log<br/>SQLite data/waf.db")]
    V --> ADM["Admin API :9000<br/>(bearer token)"]
    ADM --> K["Console :8100<br/>explain, learning inbox, simulator"]
    K -- "mode, threshold, lists, exemptions" --> ADM
```

Coraza + OWASP CRS (`waf/`) is the industry baseline used for the evaluation; it is not chained into
the gateway yet.

## What each detector catches

| Threat | rules | Coraza + CRS | payload ML | behavior ML | schema |
|---|---|---|---|---|---|
| SQL injection (plain, case/comment tricks) | yes | yes | yes | - | partly (odd characters) |
| SQL injection (double-encoded, novel forms) | partly | yes | yes (28/30 novel) | - | partly |
| XSS | yes (49.6% of CSIC XSS) | yes | yes | - | partly |
| Path traversal | yes (misses some encodings) | yes | yes | - | partly |
| Command injection | little | yes | yes (trained on it) | - | partly |
| Mass assignment (`role`, `is_admin`) | - | - | yes on the demo API (learned key) | - | **yes** (privileged / unknown field, also from OpenAPI) |
| Unknown / renamed parameters, odd paths (CSIC "structural") | - | - | - | - | **yes** (80.5% of them) |
| BOLA / IDOR (walking order ids) | - | - | - | **yes** (50% at a 5% alert budget) | - |
| Brute force / credential stuffing | **yes** (rate + failed-login rules, 92%) | - | - | partly (13%) | - |
| Known scanner user agents | yes (small weight) | yes | never a feature | never a feature | - |
| Response-side leaks (SQL errors, stack traces) | - | not evaluated | - | - | - |

Numbers are from the README (demo dataset, held-out CSIC 2010, novel-payload set). Read the caveats there:
the demo dataset is synthetic, CSIC is one synthetic shop, and the novel set is small.

## Where things live

| Part | Path |
|---|---|
| Detectors and fusion | `detection/` (`rules.py`, `ml_payload.py`, `ml_behavior.py`, `schema.py`, `fusion.py`) |
| Real-data loaders, hard negatives | `detection/external_data.py`, `detection/benign_text.py`, `detection/harmless_set.py` |
| Gateway (proxy, engine, store, admin API) | `wafgw/` (contract in `wafgw/README.md`) |
| Console | `dashboard/` |
| Demo API + traffic generator | `target_api/`, `traffic/` |
| Coraza + CRS baseline | `waf/` |
