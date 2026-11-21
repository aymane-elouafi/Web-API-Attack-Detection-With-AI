"""Load waf.toml, fill defaults, apply environment overrides."""
import os
import tomllib
from pathlib import Path

DEFAULTS = {
    "proxy": {"listen": "0.0.0.0:8080", "upstream": "http://127.0.0.1:8000", "max_body_bytes": 1048576,
              "inspect_bytes": 65536, "upstream_timeout_s": 30, "body_timeout_s": 30, "trust_forwarded": False, "workers": 1},
    "tls": {"cert": "", "key": ""},
    "engine": {"mode": "monitor", "threshold": 0.5, "on_error": "fail_open"},
    "admin": {"listen": "127.0.0.1:9000"},
    "rate_limit": {"enabled": False, "rate_per_s": 20, "burst": 40, "adaptive": True},
    "store": {"path": "data/waf.db"},
    "models": {"dir": "models"},
    "bot": {"enabled": True},
    "intel": {"enabled": True, "dir": "data/intel", "country_deny": [], "asn_deny": [], "dnsbl_enabled": False, "dnsbl_zones": []},
    "response": {"enabled": True, "action": "alert", "max_inspect_bytes": 65536,
                 "types": ["text/", "application/json", "application/xml", "application/javascript"]},
    "honeypots": {"enabled": True, "ban_minutes": 30, "canary": True,
                  "paths": ["/admin.bak", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin", "/api/internal", "/backup.sql"]},
    "coraza": {"enabled": False, "url": "http://127.0.0.1:8081", "timeout_s": 1.0},
    "reports": {"enabled": False, "dir": "data/reports", "every_h": 24, "window_h": 24, "webhook": False},
    "explainer": {"enabled": False, "url": "", "format": "openai", "model": "", "api_key_env": "", "timeout_s": 20, "send_ip": False},
    "siem": {"file": "", "syslog": "", "only_flagged": True},
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
    if env.get("WAFGW_CORAZA_URL"):                           # setting the URL switches the Coraza detector on
        cfg["coraza"].update(enabled=True, url=env["WAFGW_CORAZA_URL"])
    if env.get("WAFGW_WORKERS"):
        cfg["proxy"]["workers"] = int(env["WAFGW_WORKERS"])
    if env.get("WAFGW_TRUST_FORWARDED"):                       # demo replays send the client IP in X-Forwarded-For
        cfg["proxy"]["trust_forwarded"] = env["WAFGW_TRUST_FORWARDED"].lower() in ("1", "true", "yes")
    return cfg
