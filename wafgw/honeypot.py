"""Honeypot routes and canary tokens.

A honeypot path (/.env, /backup.sql, ...) is answered by the gateway itself with a believable fake and
never reaches the application. No real user ever asks for it, so a hit is near-certain reconnaissance.
The fakes contain canary credentials unique to this installation: if one of them later shows up in a
request (Authorization header, cookie, query or body), somebody used what they stole.
"""
import hashlib
import hmac
import secrets
import time

DEFAULT_PATHS = ["/admin.bak", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin", "/api/internal", "/backup.sql"]
DEFAULTS = {"enabled": True, "paths": DEFAULT_PATHS, "ban_minutes": 30, "canary": True}
HONEYPOT_RISK, CANARY_RISK = 0.95, 1.0


class Honeypots:
    def __init__(self, cfg: dict, store=None):
        self.cfg, self.store = {**DEFAULTS, **cfg}, store
        seed = (store and store.get("canary_seed")) or secrets.token_hex(16)
        store and store.put("canary_seed", seed)              # stable across restarts, or old canaries would go blind
        mac = lambda label: hmac.new(seed.encode(), label.encode(), hashlib.sha256).digest()
        self.canaries = {"aws_key": "AKIA" + mac("aws").hex().upper()[:16],
                         "api_key": "sk_live_" + mac("api").hex()[:32],
                         "password": "Adm1n-" + mac("pw").hex()[:10]}
        self._paths = [p.lower().rstrip("/") for p in self.cfg["paths"]]
        self._cache, self._cache_at = {}, 0.0

    def settings(self) -> dict:
        """waf.toml values overridden by what the console stored (re-read at most every 5 s)."""
        if time.monotonic() - self._cache_at > 5:
            self._cache = {**self.cfg, **((self.store and self.store.get("honeypots")) or {})}
            self._cache_at = time.monotonic()
        return self._cache

    def refresh(self) -> None:
        self._cache_at = 0.0

    def match(self, path: str) -> bool:
        if not self.settings()["enabled"]:
            return False
        p = path.lower().rstrip("/")
        return any(p == h or p.startswith(h + "/") for h in self._paths)

    def canary_used(self, text: str) -> str | None:
        """Which canary (by kind, never the value) appears in the text, if any."""
        if not self.settings()["canary"]:
            return None
        return next((kind for kind, value in self.canaries.items() if value in text), None)

    def fake(self, path: str) -> tuple[str, str]:
        """(content type, body) of a believable fake for the honeypot path."""
        c, p = self.canaries, path.lower()
        if p.endswith("/.env"):
            return "text/plain", (f"APP_ENV=production\nDEBUG=false\nDB_HOST=10.0.3.12\nDB_USER=admin\nDB_PASSWORD={c['password']}\n"
                                  f"AWS_ACCESS_KEY_ID={c['aws_key']}\nAWS_SECRET_ACCESS_KEY={hashlib.sha1(c['aws_key'].encode()).hexdigest()}\n"
                                  f"STRIPE_API_KEY={c['api_key']}\n")
        if p.endswith("/config") and ".git" in p:
            return "text/plain", (f"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n"
                                  f"\turl = https://deploy:{c['password']}@git.internal.example/shop/backend.git\n"
                                  f"\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n")
        if p.endswith((".sql", ".bak")):
            return "application/sql", (f"-- MySQL dump 10.13  Distrib 8.0.34\n-- Host: 10.0.3.12    Database: shop\n"
                                       f"INSERT INTO `users` VALUES (1,'admin','{c['password']}','admin@shop.example');\n")
        if "api/internal" in p:
            return "application/json", ('{"service":"billing-internal","version":"2.3.1",'
                                        f'"api_key":"{c["api_key"]}","endpoints":["/api/internal/refunds","/api/internal/users"]}}')
        title = "phpMyAdmin" if "phpmyadmin" in p else "Log In"
        return "text/html", (f"<!doctype html><title>{title}</title><form method=post action={path}>"
                             "<input name=log placeholder=Username><input name=pwd type=password placeholder=Password>"
                             "<button>Log In</button></form>")
