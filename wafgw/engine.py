"""Detection engine: rules + payload ML + online behavior model, fused with the same noisy-OR as the offline evaluation.

inspect() runs BEFORE the request is forwarded; observe() runs AFTER the response, because some
signals (failed logins, 404 walks) are only known once the application has answered.
"""
import hashlib
import re
import time
from functools import lru_cache
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np

from detection.ml_behavior import FEATURES, WINDOW
from detection.ml_payload import _stats, request_text
from detection.rules import StatefulRules, stateless_hits
from detection.schema import SchemaModel
from wafgw.bot import BotDetector
from wafgw.intel import Intel
from wafgw.policy import exempt_detectors, fuse

_ORDER = re.compile(r"^/orders/\d+$")


@dataclass
class Verdict:
    risk: float
    action: str                       # allow | block | monitor (monitor = would have been blocked)
    reasons: list = field(default_factory=list)   # [{detector, score, strength, detail}]
    latency_ms: float = 0.0
    status: int = 403                 # HTTP status to answer with when action == "block"
    route: str = ""

    @property
    def detectors(self) -> dict:
        return {r["detector"]: r["strength"] for r in self.reasons}


def _c(n: float) -> float:
    """Expected path length of an unsuccessful search in a binary tree (Isolation Forest normaliser)."""
    return 0.0 if n <= 1 else 1.0 if n == 2 else 2 * (np.log(n - 1) + np.euler_gamma) - 2 * (n - 1) / n


class Behavior:
    """Streaming version of detection.ml_behavior: per-client 60 s window -> Isolation Forest -> strength."""

    def __init__(self, bundle: dict, max_clients: int = 10_000):
        forest = bundle["forest"]
        self.sorted, self.cutoff, self.norm = bundle["sorted_scores"], bundle["cutoff"], _c(forest.max_samples_)
        # sklearn's per-sample scoring costs ~10 ms; walking plain Python lists of the same trees is ~0.3 ms
        self.trees = [(t.children_left.tolist(), t.children_right.tolist(), t.feature.tolist(), t.threshold.tolist(),
                       [_c(n) for n in t.n_node_samples]) for t in (e.tree_ for e in forest.estimators_)]
        self.hist: dict[str, deque] = defaultdict(deque)
        self.owners: dict[str, set] = defaultdict(set)    # order path -> sessions that requested it
        self.max_clients, self.calls = max_clients, 0

    def record(self, ip: str, session: str, path: str, ts: float) -> tuple[list, list]:
        """Add the request to the client's window; return (window entry, feature row)."""
        h = self.hist[ip]
        entry = [ts, path, 0]                              # status 0 = answer not known yet
        h.append(entry)
        while h[0][0] < ts - WINDOW:
            h.popleft()
        n = len(h)
        orders = [p for _, p, _ in h if _ORDER.match(p)]
        errors = sum(s >= 400 for _, _, s in h)
        shared = 0
        if _ORDER.match(path) and session:
            shared = len(self.owners[path] - {session})
            self.owners[path].add(session)
        row = [len(set(orders)), len(orders) / n, errors, errors / n, sum(s == 404 for _, _, s in h),
               sum(p == "/login" and s in (401, 403) for _, p, s in h), shared]
        self.calls += 1
        if self.calls % 1000 == 0:
            self._evict(ts)
        return entry, row

    def strength(self, row: list) -> tuple[float, float]:
        total = 0.0
        for left, right, feat, thr, leaf in self.trees:
            node = depth = 0
            while left[node] != -1:
                node = left[node] if row[feat[node]] <= thr[node] else right[node]
                depth += 1
            total += depth + leaf[node]
        score = 2 ** (-total / len(self.trees) / self.norm)
        p = np.searchsorted(self.sorted, score, side="right") / len(self.sorted)
        return score, float(np.clip(0.5 * (p / self.cutoff) ** 4, 0, 1))   # same mapping as detection.fusion

    def _evict(self, now: float) -> None:
        for ip in [ip for ip, h in self.hist.items() if not h or h[-1][0] < now - 10 * WINDOW]:
            del self.hist[ip]
        if len(self.hist) > self.max_clients or len(self.owners) > 50_000:
            self.hist.clear()                              # shortcut: drop all state, then re-learn within 60 s
            self.owners.clear()


class Engine:
    def __init__(self, cfg: dict, store=None):
        e, models = cfg["engine"], Path(cfg["models"]["dir"])
        self.store = store
        self.set_routes((store and store.get("routes")) or cfg.get("routes", []), persist=False)
        self.mode = (store and store.get("mode")) or e["mode"]
        self.threshold = (store and store.get("threshold")) or e["threshold"]
        self.rl = cfg["rate_limit"]
        self.buckets: dict[str, list] = {}
        self.risk_ewma: dict[str, float] = {}                 # per client: recent average risk, drives the adaptive rate limit
        self.bot = BotDetector() if cfg.get("bot", {}).get("enabled", True) else None
        i = cfg.get("intel", {})
        self.intel = Intel(i.get("dir", "data/intel"), i.get("country_deny", ()), i.get("asn_deny", ()), i.get("dnsbl_zones", ()),
                           i.get("dnsbl_enabled", False)) if i.get("enabled", True) else None
        if self.intel and store and (pol := store.get("intel_policy")):
            self.intel.set_policy(pol.get("country_deny"), pol.get("asn_deny"))
        self.rules = StatefulRules()
        self.models_dir, self.reload_every = models, 5.0
        self._payload_score = lru_cache(maxsize=4096)(self._score_payload)   # sklearn costs ~2 ms; repeated requests are common
        self.payload = self.behavior = self.schema = None
        self._stamps: dict[str, tuple | None] = {}
        self.reload_errors: dict[str, str] = {}
        self.reload_models()
        self._next_check = time.monotonic() + self.reload_every
        self.inspect_bytes = cfg["proxy"]["inspect_bytes"]

    _LOADERS = {"payload.joblib": ("payload", joblib.load),
                "behavior.joblib": ("behavior", lambda p: Behavior(joblib.load(p))),
                "schema.json": ("schema", lambda p: SchemaModel.from_json(p.read_text()))}

    def reload_models(self) -> list[str]:
        """Load every model file that is new, changed or gone; a broken file keeps the old model running."""
        changed = []
        for fname, (attr, load) in self._LOADERS.items():
            path = self.models_dir / fname
            st = path.stat() if path.exists() else None
            stamp = (st.st_mtime_ns, st.st_size) if st else None
            if stamp == self._stamps.get(fname):
                continue
            self._stamps[fname] = stamp                       # also on failure, so a bad file is not retried every request
            try:
                new = load(path) if st else None
            except Exception as exc:                          # half-written or corrupt file
                self.reload_errors[fname] = f"{type(exc).__name__}: {exc}"[:200]
                continue
            self.reload_errors.pop(fname, None)
            old = getattr(self, attr)
            if attr == "behavior" and old and new:            # keep the live per-client windows across a model swap
                new.hist, new.owners = old.hist, old.owners
            setattr(self, attr, new)
            if attr == "payload":
                self._payload_score.cache_clear()
            changed.append(attr)
        return changed

    def reload_policy(self) -> None:
        """Re-read mode, threshold, routes and exemptions from the store (settings changed outside this process)."""
        if not self.store:
            return
        self.mode = self.store.get("mode") or self.mode
        self.threshold = self.store.get("threshold") or self.threshold
        self.set_routes(self.store.get("routes") or self.routes, persist=False)
        self.store.exemption_cache = self.store.exemptions()

    def reload(self) -> dict:
        """Admin-triggered: models + policy, no restart."""
        changed = self.reload_models()
        if self.intel:
            self.intel.reload()
        self.reload_policy()
        return {"reloaded": changed, "errors": self.reload_errors, "mode": self.mode, "threshold": self.threshold}

    def _score_payload(self, text: str, stats: tuple) -> float:
        return float(self.payload.score([text], np.array([stats]))[0])

    def set_mode(self, mode: str | None = None, threshold: float | None = None) -> None:
        if mode is not None:
            if mode not in ("monitor", "block"):
                raise ValueError("mode must be monitor or block")
            self.mode = mode
            self.store and self.store.put("mode", mode)
        if threshold is not None:
            if not 0 < threshold <= 1:
                raise ValueError("threshold must be in (0, 1]")
            self.threshold = threshold
            self.store and self.store.put("threshold", threshold)

    def set_routes(self, routes: list, persist: bool = True) -> None:
        for r in routes:
            if not str(r.get("prefix", "")).startswith("/") or r.get("mode", "monitor") not in ("monitor", "block"):
                raise ValueError("each route needs a prefix starting with / and mode monitor or block")
        self.routes = sorted(routes, key=lambda r: -len(r["prefix"]))
        if persist and self.store:
            self.store.put("routes", routes)

    def route_for(self, path: str) -> dict:
        return next((r for r in self.routes if path.startswith(r["prefix"])), {})

    def _bucket_ok(self, ip: str, now: float, route: dict | None = None) -> bool:
        """Token bucket per client. A route may set its own rate_per_s / burst; with adaptive on, a client whose
        recent risk is high refills slower and has a smaller burst (down to 15% for a client that is always flagged)."""
        rate, burst = (route or {}).get("rate_per_s", self.rl["rate_per_s"]), (route or {}).get("burst", self.rl["burst"])
        if self.rl.get("adaptive", True):
            scale = 1 - 0.85 * self.risk_ewma.get(ip, 0.0)
            rate, burst = rate * scale, max(burst * scale, 2)
        tokens, last = self.buckets.get(ip, (burst, now))
        tokens = min(burst, tokens + (now - last) * rate)
        self.buckets[ip] = (tokens - 1, now) if tokens >= 1 else (tokens, now)
        if len(self.buckets) > 50_000:
            self.buckets.clear()
        return tokens >= 1

    def inspect(self, info: dict) -> Verdict:
        """info: method, path, query, body, user_agent, client_ip, session, ts."""
        t0 = time.perf_counter()
        if time.monotonic() >= self._next_check:              # cheap: three stat() calls every few seconds
            self._next_check = time.monotonic() + self.reload_every
            self.reload_models()
            self.intel and self.intel.reload_if_changed()
        route = self.route_for(info["path"])
        v = self._decide(info, route)
        v.route, v.latency_ms = route.get("prefix", ""), (time.perf_counter() - t0) * 1000
        return v

    def _decide(self, info: dict, route: dict) -> Verdict:
        ip, now = info["client_ip"], info["ts"]
        if route.get("disabled"):
            return Verdict(0.0, "allow", [{"detector": "route", "score": 0, "strength": 0, "detail": "inspection disabled"}])
        if self.store and self.store.listed(ip, "allow"):
            return Verdict(0.0, "allow", [{"detector": "allow_list", "score": 0, "strength": 0, "detail": ip}])
        if self.store and self.store.listed(ip, "deny"):
            return Verdict(1.0, "block", [{"detector": "deny_list", "score": 1, "strength": 1, "detail": ip}])
        if self.intel and (hit := self.intel.allowed(ip)):
            return Verdict(0.0, "allow", [{"detector": "intel_allow", "score": 0, "strength": 0, "detail": f"allowlisted in {hit['file']}"}])
        if self.rl["enabled"] and not self._bucket_ok(ip, now, route):
            return Verdict(1.0, "block", [{"detector": "rate_limit", "score": 1, "strength": 1, "detail": "too many requests"}], status=429)

        body = info["body"][: self.inspect_bytes]
        hits = stateless_hits(info["query"], body, info["user_agent"]) + self.rules.check(now, ip, info["path"], 0)
        score = sum(sev for _, sev in hits)
        reasons = [{"detector": "rules", "score": score, "strength": min(score / 10, 1),
                    "detail": ",".join(h for h, _ in hits)}]
        if self.payload is not None:
            text, values = request_text(info["method"], info["path"], info["query"], body)
            p = self._payload_score(text, tuple(_stats(values)))
            reasons.append({"detector": "payload ML", "score": round(p, 4), "strength": p, "detail": ""})
        if self.behavior is not None:
            info["_entry"], row = self.behavior.record(ip, info["session"], info["path"], now)
            raw, s = self.behavior.strength(row)
            reasons.append({"detector": "behavior", "score": round(raw, 4), "strength": s,
                            "detail": dict(zip(FEATURES, (round(x, 2) for x in row)))})
        if self.schema is not None and route.get("schema", True):
            found = self.schema.score(info["method"], info["path"], info["query"], body)
            if found:
                reasons.append({"detector": "schema", "score": len(found), "strength": self.schema.strength(found),
                                "detail": "; ".join(f"{f['kind']}: {f['detail']}" for f in found[:5])})
        cz = info.get("coraza")
        if cz is not None:                                    # Coraza+CRS verdict fetched by the proxy; score 5 = its own alert level
            reasons.append({"detector": "coraza", "score": cz["score"], "strength": min(cz["score"] / 10, 1),
                            "detail": cz["rules"] or cz.get("error", "")})
        if self.bot is not None:
            s, detail, info["_bot_entry"] = self.bot.inspect(info)
            if s:
                reasons.append({"detector": "bot", "score": round(s, 3), "strength": s, "detail": detail})
        if self.intel is not None and (found := self.intel.check(ip))[0]:
            reasons.append({"detector": "intel", "score": found[0], "strength": found[0], "detail": found[1]})
        silenced = exempt_detectors(self.store.exemption_cache, info["path"], info["query"], body) if self.store else set()
        for r in reasons:
            if r["detector"] in silenced and r["strength"] > 0:
                r["detail"], r["strength"] = f"exempt (was {r['strength']:.2f}) {r['detail']}".strip(), 0.0
        risk = fuse({r["detector"]: r["strength"] for r in reasons})
        thr, mode = route.get("threshold", self.threshold), route.get("mode", self.mode)
        action = "allow" if risk < thr else ("block" if mode == "block" else "monitor")
        self.risk_ewma[ip] = 0.8 * self.risk_ewma.get(ip, 0.0) + 0.2 * risk
        if len(self.risk_ewma) > 50_000:
            self.risk_ewma.clear()
        return Verdict(risk, action, [r for r in reasons if r["strength"] > 0] or reasons[:1])

    def observe(self, info: dict, status: int) -> None:
        """Feed the application's answer back into the stateful detectors."""
        if "_entry" in info:
            info["_entry"][2] = status
        if "_bot_entry" in info:
            info["_bot_entry"][2] = status
        if info["path"] == "/login" and status in (401, 403):
            self.rules.failures[info["client_ip"]].append(info["ts"])


def session_id(headers) -> str:
    """Opaque id of the caller's credential (never the credential itself); '' when anonymous."""
    cred = headers.get("authorization") or headers.get("cookie") or ""
    return hashlib.sha256(cred.encode()).hexdigest()[:16] if cred else ""
