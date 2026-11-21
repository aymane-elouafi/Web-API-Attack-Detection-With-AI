"""SQLite (WAL) event log, IP lists and settings.

Events are written by a background thread, so a request never waits for the database.
Event columns are the contract with the dashboard (see wafgw/README.md).
"""
import ipaddress
import json
import queue
import re
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, request_id TEXT, client_ip TEXT, method TEXT,
  host TEXT, path TEXT, query TEXT, user_agent TEXT, body_snippet TEXT, upstream_status INTEGER, action TEXT,
  risk REAL, detectors TEXT, reasons TEXT, latency_ms REAL, route TEXT);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_ip ON events(client_ip);
CREATE TABLE IF NOT EXISTS lists(ip TEXT PRIMARY KEY, kind TEXT, note TEXT, created REAL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS exemptions(id INTEGER PRIMARY KEY, prefix TEXT, param TEXT, detector TEXT, note TEXT, created REAL);
CREATE TABLE IF NOT EXISTS feedback(event_id INTEGER PRIMARY KEY, verdict TEXT, note TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, detail TEXT);
"""
COLUMNS = ["ts", "request_id", "client_ip", "method", "host", "path", "query", "user_agent", "body_snippet",
           "upstream_status", "action", "risk", "detectors", "reasons", "latency_ms", "route", "response_flags", "resp_bytes"]
ADDED = {"events": {"response_flags": "TEXT", "resp_bytes": "INTEGER"}, "lists": {"expires": "REAL"}}   # additive migrations
_SECRET = re.compile(r'''(?ix)("?[\w-]*(?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|authorization|cvv|card(?:number)?)[\w-]*"?\s*[:=]\s*)
                         ("(?:[^"\\]|\\.)*"|[^&\s,}]+)''')


def redact(text: str, limit: int = 2048) -> str:
    """Hide the value of anything that looks like a password / token, then cut to `limit`."""
    mask = lambda m: m.group(1) + ('"***"' if m.group(2).startswith('"') else "***")
    return _SECRET.sub(mask, text)[:limit]


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        for table, cols in ADDED.items():                 # older databases get the new columns, nothing is rewritten
            have = {r[1] for r in self._db.execute(f"PRAGMA table_info({table})")}
            for col, typ in cols.items():
                if col not in have:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        self._db.commit()
        self._queue: queue.Queue = queue.Queue()
        self._nets: dict[str, list] = {"allow": [], "deny": []}
        self._expires: dict = {}                          # network -> unix time after which the entry no longer applies
        for ip, kind, exp in self._db.execute("SELECT ip, kind, expires FROM lists"):
            net = ipaddress.ip_network(ip, strict=False)
            self._nets[kind].append(net)
            if exp:
                self._expires[net] = exp
        self.exemption_cache = self.exemptions()          # read on every request by the engine, so kept in memory
        threading.Thread(target=self._writer, daemon=True).start()

    # --- events ---------------------------------------------------------------------------------
    def log(self, event: dict) -> None:
        self._queue.put(event)

    def flush(self) -> None:
        self._queue.join()

    def _writer(self) -> None:
        sql = f"INSERT INTO events({','.join(COLUMNS)}) VALUES({','.join('?' * len(COLUMNS))})"
        while True:
            batch = [self._queue.get()]
            while len(batch) < 100 and not self._queue.empty():
                batch.append(self._queue.get_nowait())
            try:
                with self._lock:
                    self._db.executemany(sql, [[e.get(c) for c in COLUMNS] for e in batch])
                    self._db.commit()
            except sqlite3.Error:
                pass  # shortcut: a failed log write is dropped, never allowed to hurt traffic
            for _ in batch:
                self._queue.task_done()

    def events(self, since=0.0, action=None, ip=None, path=None, min_risk=0.0, before_id=None, limit=100,
               until=None, flagged=False, traps=False) -> list[dict]:
        where, args = ["ts >= ?", "risk >= ?"], [since, min_risk]
        if flagged:                                      # blocked or would_block (used by incidents and reports)
            where.append("action != 'allowed'")
        if traps:                                        # response leaks, honeypot hits, canary use: found even in a busy log
            where.append("((response_flags IS NOT NULL AND response_flags != '[]') OR reasons LIKE '%\"honeypot\"%' OR reasons LIKE '%\"canary_used\"%')")
        for cond, val in [("action = ?", action), ("client_ip = ?", ip), ("path LIKE ?", path and f"%{path}%"),
                          ("id < ?", before_id), ("ts < ?", until)]:
            if val is not None:
                where.append(cond)
                args.append(val)
        with self._lock:
            cur = self._db.execute(f"SELECT id,{','.join(COLUMNS)} FROM events WHERE {' AND '.join(where)} "
                                   f"ORDER BY id DESC LIMIT ?", [*args, min(int(limit), 50000 if flagged else 1000)])
            names = [d[0] for d in cur.description]
            rows = [dict(zip(names, r)) for r in cur.fetchall()]
        for r in rows:
            r["detectors"], r["reasons"] = json.loads(r["detectors"] or "{}"), json.loads(r["reasons"] or "[]")
            r["response_flags"] = json.loads(r["response_flags"] or "[]")
        return rows

    def flagged(self, since=0.0, until=None, limit=5000) -> list[dict]:
        """Flagged events in [since, until), newest first (one query: paging by id re-scans the table every page)."""
        return self.events(since=since, until=until, flagged=True, limit=limit)

    def stats(self, since_s: int = 3600) -> dict:
        since = time.time() - since_s
        with self._lock:
            q = lambda sql, *a: self._db.execute(sql, [since, *a]).fetchall()
            total, avg_risk = q("SELECT COUNT(*), COALESCE(AVG(risk),0) FROM events WHERE ts >= ?")[0]
            by_action = dict(q("SELECT action, COUNT(*) FROM events WHERE ts >= ? GROUP BY action"))
            top_ips = [{"ip": i, "requests": n, "flagged": f} for i, n, f in q(
                "SELECT client_ip, COUNT(*), SUM(action != 'allowed') FROM events WHERE ts >= ? "
                "GROUP BY client_ip ORDER BY 2 DESC LIMIT 5")]
            top_paths = [{"path": p, "requests": n, "flagged": f} for p, n, f in q(
                "SELECT path, COUNT(*), SUM(action != 'allowed') FROM events WHERE ts >= ? "
                "GROUP BY path ORDER BY 3 DESC, 2 DESC LIMIT 5")]
            timeline = [{"t": t, "requests": n, "flagged": f} for t, n, f in q(
                "SELECT CAST(ts/60 AS INT)*60, COUNT(*), SUM(action != 'allowed') FROM events WHERE ts >= ? "
                "GROUP BY 1 ORDER BY 1")]
            lat = [r[0] for r in q("SELECT latency_ms FROM events WHERE ts >= ? ORDER BY latency_ms LIMIT 100000")]
            leaks = q("SELECT COUNT(*) FROM events WHERE ts >= ? AND response_flags IS NOT NULL AND response_flags != '[]'")[0][0]
        pick = lambda p: round(lat[min(len(lat) - 1, int(len(lat) * p))], 3) if lat else 0.0
        return {"window_s": since_s, "total": total, "avg_risk": round(avg_risk, 4), "by_action": by_action,
                "latency_ms": {"p50": pick(0.5), "p95": pick(0.95), "max": round(lat[-1], 3) if lat else 0.0},
                "top_ips": top_ips, "top_paths": top_paths, "timeline": timeline, "leaks": leaks}

    # --- lists ----------------------------------------------------------------------------------
    def listed(self, ip: str, kind: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        now = time.time()
        for net in list(self._nets[kind]):
            if addr in net:
                if self._expires.get(net, now + 1) <= now:         # temporary ban (honeypot) has run out
                    self.remove_list(str(net.network_address) if net.num_addresses == 1 else str(net))
                    continue
                return True
        return False

    def lists(self) -> list[dict]:
        with self._lock:
            cur = self._db.execute("SELECT ip, kind, note, created, expires FROM lists ORDER BY created")
            return [dict(zip(("ip", "kind", "note", "created", "expires"), r)) for r in cur.fetchall()]

    def add_list(self, ip: str, kind: str, note: str = "", ttl_s: float | None = None) -> None:
        net = ipaddress.ip_network(ip, strict=False)          # raises ValueError on garbage
        if kind not in self._nets:
            raise ValueError("kind must be allow or deny")
        self.remove_list(ip)
        with self._lock:
            self._db.execute("INSERT INTO lists(ip,kind,note,created,expires) VALUES(?,?,?,?,?)",
                             (ip, kind, note, time.time(), time.time() + ttl_s if ttl_s else None))
            self._db.commit()
        self._nets[kind].append(net)
        if ttl_s:
            self._expires[net] = time.time() + ttl_s

    def remove_list(self, ip: str) -> bool:
        net = ipaddress.ip_network(ip, strict=False)
        with self._lock:
            n = self._db.execute("DELETE FROM lists WHERE ip = ?", (ip,)).rowcount
            self._db.commit()
        for nets in self._nets.values():
            if net in nets:
                nets.remove(net)
        self._expires.pop(net, None)
        return bool(n)

    # --- settings -------------------------------------------------------------------------------
    def get(self, key: str, default=None):
        with self._lock:
            row = self._db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key: str, value) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))
            self._db.commit()

    # --- exemptions, feedback, audit ------------------------------------------------------------
    def _rows(self, sql: str, args=()) -> list[dict]:
        with self._lock:
            cur = self._db.execute(sql, args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def exemptions(self) -> list[dict]:
        return self._rows("SELECT id, prefix, param, detector, note, created FROM exemptions ORDER BY id")

    def add_exemption(self, prefix: str, detector: str, param: str = "", note: str = "") -> int:
        from wafgw.policy import DETECTORS
        if not prefix.startswith("/") or detector not in DETECTORS:
            raise ValueError(f"prefix must start with / and detector be one of {', '.join(DETECTORS)}")
        with self._lock:
            cur = self._db.execute("INSERT INTO exemptions(prefix,param,detector,note,created) VALUES(?,?,?,?,?)",
                                   (prefix, param or "", detector, note, time.time()))
            self._db.commit()
        self.exemption_cache = self.exemptions()
        return cur.lastrowid

    def remove_exemption(self, ex_id: int) -> bool:
        with self._lock:
            n = self._db.execute("DELETE FROM exemptions WHERE id = ?", (ex_id,)).rowcount
            self._db.commit()
        self.exemption_cache = self.exemptions()
        return bool(n)

    def event(self, event_id: int) -> dict | None:
        rows = self.events(before_id=event_id + 1, limit=1)
        return rows[0] if rows and rows[0]["id"] == event_id else None

    def set_feedback(self, event_id: int, verdict: str, note: str = "") -> None:
        if verdict not in ("benign", "attack"):
            raise ValueError("verdict must be benign or attack")
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO feedback VALUES(?,?,?,?)", (event_id, verdict, note, time.time()))
            self._db.commit()

    def feedback(self) -> list[dict]:
        return self._rows("SELECT event_id, verdict, note, ts FROM feedback ORDER BY ts DESC")

    def audit(self, actor: str, action: str, detail: str = "") -> None:
        with self._lock:
            self._db.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)", (time.time(), actor, action, detail[:300]))
            self._db.commit()

    def audit_log(self, limit: int = 200) -> list[dict]:
        return self._rows("SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?", (min(limit, 1000),))
