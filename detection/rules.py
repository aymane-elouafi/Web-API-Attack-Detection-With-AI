"""Rules-based detector: the classic WAF-style baseline.

It works like OWASP ModSecurity CRS in "anomaly scoring" mode:
  * every rule that matches adds points (its severity) to the request;
  * a request whose total score reaches THRESHOLD is flagged.

Two kinds of rules:
  1. STATELESS signature rules -- look at one request at a time
     (SQL injection, XSS, path traversal, encoding tricks, scanner user agents).
  2. STATEFUL rules -- look at how often one client does something
     (too many requests, too many failed logins).

Before matching, request values are normalized the way a WAF does it: URL-decode
once (what the server itself does), remove /* comments */, squeeze whitespace,
lowercase. That defeats simple tricks (case changes, comment padding) but not
everything -- double encoding, for example, only earns a "suspicious" score.

Deliberately NOT included: app-specific rules (e.g. "PUT /users/me must not
accept a role field") and anything that needs to know who owns which order.
A generic WAF cannot know those -- that gap is where the AI should help.
"""
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import parse_qsl

import pandas as pd

THRESHOLD = 5          # anomaly score at/above which a request is flagged


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: int          # points added to the request score
    regex: re.Pattern
    target: str = "values"  # "values" = decoded query/body values, or "user_agent"


def _rule(id_: str, name: str, severity: int, pattern: str, target: str = "values") -> Rule:
    return Rule(id_, name, severity, re.compile(pattern, re.I), target)


RULES = [
    # --- SQL injection ------------------------------------------------------
    _rule("SQLI-1", "Boolean tautology (quote + OR/AND ...)", 5, r"""['"]\s*\)?\s*(or|and)\s*\(?\s*(\d|\(|true\b|false\b|['"]\s*[^'"]*['"]?\s*(=|like\b|<|>)|['"]\s*['"])"""),
    _rule("SQLI-2", "UNION SELECT", 5, r"union(\s+all)?\s+select"),
    _rule("SQLI-3", "Stacked destructive statement", 5, r";\s*(drop|delete|insert|update|alter|truncate)\s"),
    _rule("SQLI-4", "Time-delay function", 5, r"\b(sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay"),
    _rule("SQLI-5", "Schema probing", 5, r"sqlite_master|information_schema|sys\.tables"),
    _rule("SQLI-6", "Quote followed by SQL comment", 5, r"""['"]\s*--(?!\s+[a-z]{2,}\b)"""),
    _rule("SQLI-7", "ORDER BY <n>", 3, r"order\s+by\s+\d+"),
    _rule("SQLI-8", "Ends with SQL comment", 3, r"--\s*$"),
    _rule("SQLI-9", "SELECT ... FROM", 3, r"select\s.+\sfrom\s"),
    # --- Cross-site scripting ----------------------------------------------
    _rule("XSS-1", "<script> tag", 5, r"<\s*script"),
    _rule("XSS-2", "Inline event handler", 5, r"\bon(error|load|focus|toggle|click|mouseover|mouseenter|submit|input)\s*="),
    _rule("XSS-3", "javascript: URI", 5, r"javascript\s*:"),
    _rule("XSS-4", "iframe/object/embed tag", 5, r"<\s*(iframe|object|embed)\b"),
    _rule("XSS-5", "Suspicious HTML tag", 3, r"<\s*(svg|img|body|details|input|a)\b"),
    # --- Path traversal -----------------------------------------------------
    _rule("PATH-1", "Directory traversal (../)", 5, r"\.\.[/\\]"),
    _rule("PATH-2", "Sensitive system file", 5, r"/etc/(passwd|shadow|hosts)"),
    _rule("PATH-3", ".env file", 3, r"\.env\b"),
    # --- Evasion / tooling --------------------------------------------------
    _rule("ENC-1", "Multiple URL encoding", 3, r"%[0-9a-f]{2}"),
    _rule("SCAN-1", "Known attack-tool user agent", 3,
          r"sqlmap|nikto|nessus|acunetix|masscan|gobuster|dirbuster|wfuzz|hydra", target="user_agent"),
]

# Stateful rule ids and severities (logic lives in StatefulRules)
RATE_RULE = ("RATE-1", 5)    # more than 20 requests in 10 s from one IP
AUTH_RULE = ("AUTH-1", 5)    # 5+ failed logins in 60 s from one IP

_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def normalize(text: str) -> str:
    """Comment removal + whitespace squeeze + lowercase (like CRS transformations)."""
    return re.sub(r"\s+", " ", _COMMENT.sub(" ", text)).strip().lower()


def _walk(obj):
    """Yield every string found in a parsed JSON body."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk(value)


def extract_values(query: str, body: str) -> list[str]:
    """Decoded (once) query-parameter values and JSON body strings."""
    values = [v for _, v in parse_qsl(query, keep_blank_values=True)]
    if body:
        try:
            values += list(_walk(json.loads(body)))
        except json.JSONDecodeError:
            values.append(body)
    return values


def stateless_hits(query: str = "", body: str = "", user_agent: str = "") -> list[tuple[str, int]]:
    """Return [(rule_id, severity), ...] for the signature rules that match."""
    values = [normalize(v) for v in extract_values(query, body)]
    hits: dict[str, int] = {}
    for rule in RULES:
        texts = [user_agent] if rule.target == "user_agent" else values
        if any(rule.regex.search(t) for t in texts):
            hits[rule.id] = rule.severity
    return list(hits.items())


class StatefulRules:
    """Per-IP sliding windows. Feed requests in time order."""

    def __init__(self, rate_window=10, rate_max=20, fail_window=60, fail_max=5):
        self.rate_window, self.rate_max = rate_window, rate_max
        self.fail_window, self.fail_max = fail_window, fail_max
        self.requests: dict[str, deque] = defaultdict(deque)
        self.failures: dict[str, deque] = defaultdict(deque)

    def check(self, ts: float, ip: str, path: str, status: int) -> list[tuple[str, int]]:
        hits = []
        recent = self.requests[ip]
        recent.append(ts)
        while recent and ts - recent[0] > self.rate_window:
            recent.popleft()
        if len(recent) > self.rate_max:
            hits.append(RATE_RULE)

        if path == "/login":
            fails = self.failures[ip]
            while fails and ts - fails[0] > self.fail_window:
                fails.popleft()
            if status in (401, 403):
                fails.append(ts)
            if len(fails) >= self.fail_max:
                hits.append(AUTH_RULE)
        return hits


def detect(df: pd.DataFrame, threshold: int = THRESHOLD) -> pd.DataFrame:
    """Score every request. Returns columns: id, rule_score, rule_hits, rule_flag."""
    stateful = StatefulRules()
    rows = []
    for r in df.sort_values("ts").itertuples(index=False):
        hits = stateless_hits(r.query, r.body, r.user_agent)
        hits += stateful.check(r.ts, r.client_ip, r.path, r.status)
        rows.append((r.id, sum(sev for _, sev in hits), ",".join(h for h, _ in hits)))
    out = pd.DataFrame(rows, columns=["id", "rule_score", "rule_hits"])
    out["rule_flag"] = out["rule_score"] >= threshold
    return out
