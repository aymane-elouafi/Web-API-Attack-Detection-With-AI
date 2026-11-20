"""Load waf.toml, fill defaults, apply environment overrides."""
import os
import tomllib
from pathlib import Path

DEFAULTS = {
    "proxy": {"listen": "0.0.0.0:8080", "upstream": "http://127.0.0.1:8000", "max_body_bytes": 1048576,
              "inspect_bytes": 65536, "upstream_timeout_s": 30, "trust_forwarded": False},
    "engine": {"mode": "monitor", "threshold": 0.5, "on_error": "fail_open"},
    "admin": {"listen": "127.0.0.1:9000"},
    "rate_limit": {"enabled": False, "rate_per_s": 20, "burst": 40},
    "store": {"path": "data/waf.db"},
    "models": {"dir": "models"},
    "routes": [],
}


def load(path: str | None = None) -> dict:
    path = path or os.environ.get("WAFGW_CONFIG", "waf.toml")
    user = tomllib.loads(Path(path).read_text()) if Path(path).exists() else {}
    cfg = {k: (dict(v) if isinstance(v, dict) else list(v)) for k, v in DEFAULTS.items()}
    for k, v in user.items():
        cfg[k] = {**cfg[k], **v} if isinstance(v, dict) else v
    env = os.environ
    for key, section, name in [("WAFGW_UPSTREAM", "proxy", "upstream"), ("WAFGW_MODE", "engine", "mode"),
                               ("WAFGW_DB", "store", "path"), ("WAFGW_ADMIN_LISTEN", "admin", "listen")]:
        if env.get(key):
            cfg[section][name] = env[key]
    return cfg
