"""Glue between the proxy and the response / honeypot modules (kept out of proxy.py).

Guards.inspect() reads at most `max_inspect_bytes` of a text/JSON response BEFORE any byte is sent to the
client, so a leaking response can still be redacted or replaced; anything bigger keeps streaming.
"""
import json
import time

from wafgw import response as R
from wafgw.honeypot import Honeypots


async def _chain(head: bytes, rest):
    yield head
    async for chunk in rest:
        yield chunk


class Guards:
    def __init__(self, cfg: dict, store=None):
        self.store, self.cfg, self.size = store, cfg["response"], R.SizeWatch()
        self.honeypots = Honeypots(cfg["honeypots"], store)
        self._cache, self._at = {}, 0.0

    def settings(self) -> dict:
        """waf.toml values overridden by what the console stored (re-read at most every 5 s)."""
        if time.monotonic() - self._at > 5:
            self._cache = {**self.cfg, **((self.store and self.store.get("response")) or {})}
            self._at = time.monotonic()
        return self._cache

    def refresh(self) -> None:
        self._at = 0.0
        self.honeypots.refresh()

    @staticmethod
    def upstream_headers(headers: list) -> list:
        """Ask the application for an uncompressed answer, otherwise there is nothing readable to scan."""
        return [(k, v) for k, v in headers if k != b"accept-encoding"] + [(b"accept-encoding", b"identity")]

    async def inspect(self, resp, path: str, mode: str, method: str) -> dict:
        """-> {stream | body, flags, bytes, outcome: pass|redacted|blocked}. Never raises on odd bodies."""
        rs = self.settings()
        declared = resp.headers.get("content-length")
        size = int(declared) if declared and declared.isdigit() else None
        out = {"stream": resp.aiter_raw(), "body": None, "flags": [], "bytes": size, "outcome": "pass"}
        if not rs["enabled"] or method == "HEAD" or resp.status_code in (204, 304):
            return out
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if any(ctype.startswith(t) for t in rs["types"]) and not resp.headers.get("content-encoding"):
            cap, buf, complete, it = rs["max_inspect_bytes"], bytearray(), True, out["stream"]
            async for chunk in it:
                buf += chunk
                if len(buf) > cap:
                    complete = False
                    break
            text = bytes(buf).decode("utf-8", "replace")
            flags = R.scan(text)
            if flags and not complete:
                for f in flags:
                    f["detail"] += " (first %d KB only)" % (cap // 1024)
            size = len(buf) if complete else size
            action = rs["action"] if mode == "block" else "alert"      # monitor mode never touches traffic
            if flags and action == "block" and R.strength(flags) >= 0.5:
                out["outcome"] = "blocked"
            elif complete and flags and action == "redact":
                clean = R.redact(text, flags)
                if clean != text:
                    buf, out["outcome"] = bytearray(clean.encode()), "redacted"
                    for f in flags:
                        f["detail"] += " -> redacted"
            out["flags"] = flags
            out["body"], out["stream"] = (bytes(buf), None) if complete else (None, _chain(bytes(buf), it))
        if size is not None and resp.status_code < 400:
            hit = self.size.check(path, size)
            if hit:
                out["flags"].append(hit)
        out["bytes"] = size
        return out

    @staticmethod
    def event_fields(g: dict, reasons: list) -> dict:
        """Extra event columns; the response finding is added to `reasons` only (request risk/detectors stay untouched)."""
        if not g["flags"]:
            return {"resp_bytes": g["bytes"]}
        reason = {"detector": "response", "score": len(g["flags"]), "strength": R.strength(g["flags"]),
                  "detail": "; ".join(f"{f['kind']}: {f['detail']}" for f in g["flags"][:5])}
        return {"resp_bytes": g["bytes"], "response_flags": json.dumps(g["flags"]), "reasons": json.dumps([*reasons, reason])}
