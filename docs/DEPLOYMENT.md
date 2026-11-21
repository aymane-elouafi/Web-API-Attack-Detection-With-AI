# Deployment

Verified with Docker Compose v2 on Linux (gateway + demo API + console, and the optional Coraza side-car).

## Docker Compose

```bash
cp .env.example .env            # set WAF_ADMIN_TOKEN (required; compose refuses to start without it)
docker compose up --build -d    # gateway :8080, admin 127.0.0.1:9000, console 127.0.0.1:8100, demo API (not published)
curl -i http://localhost:8080/products/search?q=laptop
```

| Service | Image | Notes |
|---|---|---|
| `gateway` | `wafgw:local` (target `gateway` of `Dockerfile.gateway`) | non-root (uid 10001), read-only root fs, `/tmp` tmpfs, all capabilities dropped. Published: client port `${GATEWAY_PORT:-8080}`, admin API on `127.0.0.1:${ADMIN_PORT:-9000}` |
| `console` | same image, `python -m dashboard` | published on `${CONSOLE_BIND:-127.0.0.1}:${CONSOLE_PORT:-8100}`; set `CONSOLE_PASSWORD` before binding to anything but localhost |
| `target` | target `target` (≈200 MB) | the intentionally vulnerable demo API. Never publish it. Replace it with your own upstream: set `WAFGW_UPSTREAM` and drop the service |
| `coraza` | `web-api-coraza:local` (24 MB, `waf/`) | profile `coraza`; side-car with `INSPECT_ONLY=1` |

Coraza as the 6th detector: `WAFGW_CORAZA_URL=http://coraza:8081 docker compose --profile coraza up --build -d`.
Without that variable the gateway ignores Coraza even if the profile runs. Image sizes: `wafgw:local` ≈ 674 MB
(Python, pandas, scikit-learn, the models), Coraza 24 MB.

Start in `monitor` mode (default, logs "would block" only), watch the Events and Learning Inbox pages for a few
days, create exemptions for false positives, then switch to `block` in the console or with
`curl -X POST -H "Authorization: Bearer $WAF_ADMIN_TOKEN" -d '{"mode":"block"}' http://127.0.0.1:9000/api/mode`.

### Persistence

| Volume | Mounted at | Holds |
|---|---|---|
| `wafdata` | `/var/lib/wafgw` | `waf.db`: events, lists, exemptions, feedback, audit log, settings (mode, threshold, routes) |
| `wafmodels` | `/app/models` | `payload.joblib`, `behavior.joblib`, `schema.json` (hot-reloaded every 5 s) |

A new `wafmodels` volume starts from the models baked into the image (trained on the synthetic dataset only,
because `data/external/` is not shipped). `docker/entrypoint.sh` trains them if the volume is empty or incomplete.
To use the stronger real-data models trained on your machine (`python -m wafgw.train`):

```bash
docker run --rm -v wafgw_wafmodels:/m -v "$PWD/models:/src:ro" python:3.12-slim cp /src/payload.joblib /src/behavior.joblib /m/
docker compose restart gateway    # or POST /api/reload on the admin API: no restart needed
```

To learn the API schema into the volume: `docker compose exec gateway python -m wafgw.schema_learn --openapi http://target:8000/openapi.json`.

### Verified end to end (test run)

Benign requests 200; SQL injection / path traversal logged as `would_block` in monitor mode and answered `403` in
block mode; events appear in the console container through the admin API; admin API `401` without the token;
container root fs read-only; the event log survived `docker compose down` / `up`. Coraza on: its rule ids
(e.g. 942100, 930100) appear in the event reasons and add to the fused risk. Latency, 150-200 sequential requests
with new query text, measured from the host: direct to the demo API inside its container 2.2 ms p50; through the
gateway 12-14 ms p50 / 15-22 ms p95 (includes Docker's port forwarding); with the Coraza side-car about +4 ms more.

## Without Docker: systemd

```ini
# /etc/systemd/system/wafgw.service
[Unit]
Description=WAF gateway
After=network-online.target

[Service]
User=waf
WorkingDirectory=/opt/wafgw
EnvironmentFile=/etc/wafgw.env              # WAF_ADMIN_TOKEN=..., WAFGW_UPSTREAM=http://127.0.0.1:3000
ExecStart=/opt/wafgw/.venv/bin/python -m wafgw
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/wafgw/data /opt/wafgw/models
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Run `python -m wafgw.train` once in `/opt/wafgw`, `systemctl enable --now wafgw`. The console is
`python -m dashboard` in a second unit with the same `EnvironmentFile`.

## TLS in front (the gateway can also terminate TLS: `[tls] cert/key`)

Caddy (automatic certificates), the gateway stays on plain HTTP behind it. Set `trust_forwarded = true`
(`WAFGW_TRUST_FORWARDED=1`) so the real client IP is read from `X-Forwarded-For`, and only then, because
anyone who can reach the gateway directly could forge it:

```
waf.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
server {
    listen 443 ssl;  server_name waf.example.com;
    ssl_certificate /etc/letsencrypt/live/waf.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/waf.example.com/privkey.pem;
    client_max_body_size 1m;                       # match [proxy] max_body_bytes
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 35s;
    }
}
```

A reverse proxy in front also covers what the gateway cannot: slow-header (slowloris) clients, WebSockets
(the gateway answers 501) and HTTP/2.

## Upgrade

```bash
git pull
docker compose build
docker compose up -d            # volumes (events, models, schema) are kept
# only if you want fresh models from the new code:
docker compose run --rm gateway python -m wafgw.train --data data/dataset.csv --out models --synthetic-only
```

## Backup

The whole state is `waf.db` (plus `schema.json` if you learned one):

```bash
docker compose exec gateway python -c "import sqlite3;sqlite3.connect('/var/lib/wafgw/waf.db').execute(\"VACUUM INTO '/var/lib/wafgw/backup.db'\")"
docker compose cp gateway:/var/lib/wafgw/backup.db ./waf-backup-$(date +%F).db   # then delete backup.db from the volume
```

(`VACUUM INTO` gives a consistent copy while the gateway runs. The backup, systemd and nginx/Caddy snippets are untested examples.) Policy can also be exported as JSON from the
console (Settings). Restore: stop the gateway, copy the file over `/var/lib/wafgw/waf.db` in the volume, start it.
