"""Incidents: group flagged events into one story per client, classify it, and write it up in plain language.

Everything here is deterministic and rule-based (no LLM). The incident dict is the contract for the console
and for wafgw/report.py; wafgw/explainer.py can optionally add an LLM-written paragraph on top of it.
"""
import re
import time
from collections import Counter
from urllib.parse import unquote_plus

GAP_S = 300                                  # quiet time that ends an incident
FLAGGED = ("blocked", "would_block")
SEVERITIES = ("low", "medium", "high", "critical")

# key -> name, base severity weight, what it is, how to fix it, and standard references (None = no fitting entry)
CATALOG = {
    "sqli": dict(name="SQL injection", weight=.8, owasp_api="API8:2019 Injection (no separate entry in the 2023 list)",
                 owasp_top10="A03:2021 Injection", cwe="CWE-89", attack="T1190 Exploit Public-Facing Application",
                 what="SQL injection tries to make the database run attacker-supplied SQL, which can expose or change any data the application can reach.",
                 fix=["Use parameterised queries / an ORM for every query; never build SQL with string formatting.",
                      "Give the application's database account only the rights it needs.",
                      "Return generic errors: SQL error text in a response helps the attacker."]),
    "xss": dict(name="Cross-site scripting", weight=.5, owasp_api=None, owasp_top10="A03:2021 Injection", cwe="CWE-79",
                attack="T1059.007 JavaScript",
                what="Cross-site scripting stores or reflects script that later runs in another user's browser, where it can steal sessions or act as that user.",
                fix=["Escape output for the context it is rendered in (HTML, attribute, JS).",
                     "Sanitise rich text on input with an allow-list, and set a restrictive Content-Security-Policy."]),
    "path_traversal": dict(name="Path traversal", weight=.7, owasp_api=None, owasp_top10="A01:2021 Broken Access Control", cwe="CWE-22",
                           attack="T1190 Exploit Public-Facing Application",
                           what="Path traversal uses ../ sequences or absolute paths to read files outside the folder the application meant to serve.",
                           fix=["Resolve the requested path and verify it stays inside the allowed directory.",
                                "Prefer file ids over file names in the API; run the service without access to sensitive files."]),
    "bola": dict(name="Broken object level authorization (BOLA / IDOR)", weight=.8, owasp_api="API1:2023 Broken Object Level Authorization",
                 owasp_top10="A01:2021 Broken Access Control", cwe="CWE-639", attack="T1190 Exploit Public-Facing Application",
                 what="The client walked through many object ids, or touched objects other users own. If the application does not check ownership, it hands over other people's data.",
                 fix=["Check on the server that the authenticated user owns or may access the requested object, on every request.",
                      "Use unpredictable ids (UUIDs) and rate-limit enumeration of ids."]),
    "mass_assignment": dict(name="Mass assignment / privileged field", weight=.8, owasp_api="API3:2023 Broken Object Property Level Authorization",
                            owasp_top10="A01:2021 Broken Access Control", cwe="CWE-915", attack="T1190 Exploit Public-Facing Application",
                            what="A request set a field the client should not control (for example role or is_admin). If the API binds request fields straight onto the object, the caller can promote themselves.",
                            fix=["Bind only an explicit allow-list of fields on update; never copy the whole request body onto the model.",
                                 "Keep privileged properties (role, is_admin, balance) writable only through admin-only code paths."]),
    "brute_force": dict(name="Credential brute force", weight=.6, owasp_api="API2:2023 Broken Authentication",
                        owasp_top10="A07:2021 Identification and Authentication Failures", cwe="CWE-307", attack="T1110 Brute Force",
                        what="Many failed logins in a short time: someone is guessing passwords or replaying leaked credentials.",
                        fix=["Add lockout or progressive delays per account and per IP, and require MFA for sensitive accounts.",
                             "Check passwords against breached lists and alert owners when a login succeeds after many failures."]),
    "scanner": dict(name="Scanner / attack tool", weight=.3, owasp_api=None, owasp_top10="A05:2021 Security Misconfiguration", cwe="CWE-200",
                    attack="T1595.002 Vulnerability Scanning",
                    what="The client identifies itself as, or behaves like, an automated security tool probing for known weaknesses.",
                    fix=["Ban the source and keep an eye on what it probed: scanners show which endpoints are discoverable.",
                         "Remove or protect endpoints the scan reached that should not be public."]),
    "flood": dict(name="Request flood", weight=.3, owasp_api="API4:2023 Unrestricted Resource Consumption", owasp_top10=None, cwe="CWE-770",
                  attack="T1499 Endpoint Denial of Service",
                  what="The client sent far more requests than a person would, which can exhaust the service or hide other attacks.",
                  fix=["Enable the gateway rate limit and per-route limits for expensive endpoints."]),
    "api_misuse": dict(name="Unexpected API usage", weight=.3, owasp_api="API9:2023 Improper Inventory Management", owasp_top10=None, cwe="CWE-20",
                       attack="T1595 Active Scanning",
                       what="Requests did not fit the API: unknown endpoints, parameters or methods, missing or mistyped fields. Typical of probing and of clients written against a different version.",
                       fix=["Check whether the endpoint should exist; if it is legitimate, add it to the OpenAPI file and relearn the schema.",
                            "Reject unknown fields in the application too."]),
    "evasion": dict(name="Encoding evasion", weight=.3, owasp_api=None, owasp_top10="A03:2021 Injection", cwe="CWE-116", attack="T1027 Obfuscated Files or Information",
                    what="The payload used repeated URL encoding, which is a common way to slip past naive filters.",
                    fix=["Normalise and decode input once, early, and validate the decoded value."]),
    "malicious_payload": dict(name="Suspicious payload", weight=.5, owasp_api=None, owasp_top10="A03:2021 Injection", cwe="CWE-20",
                              attack="T1190 Exploit Public-Facing Application",
                              what="The payload model found text that looks like an attack, though no specific signature matched.",
                              fix=["Inspect the request in the console; if it is harmless, mark it benign so the Learning Inbox can propose an exemption."]),
    "anomaly": dict(name="Unusual client behavior", weight=.2, owasp_api=None, owasp_top10=None, cwe=None, attack=None,
                    what="The client behaved unlike normal users, but not in a way that matches a known attack.",
                    fix=["Check the client's other requests (Threats page) before acting."]),
}
SHORT = {"sqli": "SQL injection", "xss": "XSS", "path_traversal": "path traversal", "bola": "BOLA", "mass_assignment": "mass assignment",
         "brute_force": "brute force", "scanner": "scanner", "flood": "request flood", "api_misuse": "API probing", "evasion": "encoding evasion",
         "malicious_payload": "suspicious payload", "anomaly": "unusual behavior"}
PRIMARY = {"sqli", "xss", "path_traversal", "bola", "mass_assignment", "brute_force"}     # techniques that count for the multi-technique bonus
RULE_PREFIX = {"SQLI": "sqli", "XSS": "xss", "PATH": "path_traversal", "ENC": "evasion", "SCAN": "scanner", "RATE": "flood", "AUTH": "brute_force"}
TEXT_HINTS = [("sqli", re.compile(r"union\s+(all\s+)?select|'\s*(or|and)\s|sleep\s*\(|sqlite_master|information_schema|;\s*drop\s", re.I)),
              ("xss", re.compile(r"<\s*script|on\w+\s*=|javascript:|<\s*(svg|img|iframe)", re.I)),
              ("path_traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|%2e%2e", re.I))]
LIVE = ("rules", "payload ML", "behavior", "schema", "coraza")     # detectors that count as independent evidence
INJECTION_LIKE = {"sqli", "xss", "path_traversal", "bola", "mass_assignment", "malicious_payload"}


def template(path: str) -> str:
    return re.sub(r"/\d+", "/{id}", path)


def classify(ev: dict) -> list[str]:
    """Attack classes one flagged event belongs to (ordered, no duplicates)."""
    out: list[str] = []
    add = lambda k: k in out or out.append(k)
    reasons = {r["detector"]: r for r in ev["reasons"]}
    for rid in filter(None, str(reasons.get("rules", {}).get("detail", "")).split(",")):
        if rid.split("-")[0] in RULE_PREFIX and not rid.startswith("exempt"):
            add(RULE_PREFIX[rid.split("-")[0]])
    for part in str(reasons.get("schema", {}).get("detail", "")).split("; "):
        if part.strip():
            add("mass_assignment" if part.startswith("privileged_field") else "api_misuse")
    beh = reasons.get("behavior")
    if beh and beh["strength"] >= .3 and isinstance(beh["detail"], dict):
        d = beh["detail"]
        if d.get("order_ids", 0) >= 4 or (d.get("not_found", 0) >= 3 and d.get("order_share", 0) >= .5):
            add("bola")
        if d.get("failed_logins", 0) >= 5:
            add("brute_force")
    ml = reasons.get("payload ML")
    if ml and ml["strength"] >= .5 and not (set(out) & INJECTION_LIKE):
        text = unquote_plus(f"{ev['query']} {ev['body_snippet'] or ''}")
        hint = next((k for k, rx in TEXT_HINTS if rx.search(text)), "malicious_payload")
        add(hint)
    return out or ["anomaly"]


def _statuses(events: list[dict]) -> dict:
    c = Counter()
    for e in events:
        s = e["upstream_status"] or 0
        c["blocked" if e["action"] == "blocked" else f"{s // 100}xx" if s else "none"] += 1
    return dict(c)


def _outcome(events: list[dict], classes: list[str], context: list[dict]) -> dict:
    """Did the attack probably work? Uses what the application answered (upstream_status) and, for logins, later successes."""
    serious = [e for e in events if set(e["_classes"]) & (INJECTION_LIKE | {"brute_force"}) and e["action"] != "blocked"]
    if events and all(e["action"] == "blocked" for e in events):
        return {"level": "blocked", "detail": "Every request was stopped by the gateway before it reached the application."}
    if "brute_force" in classes and context:
        fails, wins = 0, 0
        for e in sorted(context, key=lambda e: e["ts"]):
            if e["path"] == "/login" or "login" in e["path"]:
                if e["upstream_status"] in (401, 403):
                    fails += 1
                elif e["upstream_status"] and 200 <= e["upstream_status"] < 300 and fails >= 5:
                    wins += 1
        if wins:
            return {"level": "possibly_succeeded", "detail": f"A login succeeded after {fails} failed attempts from this client: the account may be compromised."}
    ok = [e for e in serious if e["upstream_status"] and 200 <= e["upstream_status"] < 300 and not (set(e["_classes"]) <= {"brute_force"})]
    err = [e for e in serious if e["upstream_status"] and e["upstream_status"] >= 500]
    if ok:
        return {"level": "possibly_succeeded", "detail": f"{len(ok)} of {len(serious)} attack requests got a 2xx answer, so the application accepted them. Check whether data was exposed or changed."}
    if err:
        return {"level": "failed", "detail": f"No attack request was accepted, but {len(err)} caused a server error (5xx): the input reached application logic and should be fixed."}
    if serious:
        return {"level": "failed", "detail": "The application rejected the attack requests (4xx), so they most likely did not work."}
    return {"level": "unknown", "detail": "These signals are about behavior or probing, not about a request that could succeed or fail."}


def _severity(classes: list[str], max_risk: float, outcome: dict, n_events: int) -> tuple[str, float]:
    """0-1 score: how bad the worst technique is, scaled by risk, plus evidence it worked, volume and breadth."""
    score = max(CATALOG[k]["weight"] for k in classes) * (.6 + .4 * max_risk)
    score += {"possibly_succeeded": .1, "blocked": -.25}.get(outcome["level"], 0)
    score += min(.1, n_events / 300) + .05 * min(2, max(0, len(set(classes) & PRIMARY) - 1))
    score = max(0.0, min(1.0, score))
    return ("critical" if score >= .95 else "high" if score >= .65 else "medium" if score >= .4 else "low"), round(score, 3)


def _confidence(detectors: Counter, max_risk: float) -> str:
    k = sum(1 for d in LIVE if detectors.get(d))
    return "high" if k >= 3 or (k == 2 and max_risk >= .9) else "medium" if k == 2 or max_risk >= .8 else "low"


def _timeline(events: list[dict], limit: int = 40) -> list[dict]:
    """Consecutive requests with the same shape collapse into one step (a 300-request brute force is one line)."""
    steps: list[dict] = []
    for e in events:
        sig = (tuple(e["_classes"]), e["method"], template(e["path"]))
        if steps and steps[-1]["_sig"] == sig:
            s = steps[-1]
            s["count"] += 1
            s["end_ts"], s["max_risk"] = e["ts"], max(s["max_risk"], e["risk"])
            s["statuses"][e["upstream_status"] or 0] += 1
            continue
        steps.append({"_sig": sig, "ts": e["ts"], "end_ts": e["ts"], "count": 1, "method": e["method"], "path": template(e["path"]),
                      "classes": list(e["_classes"]), "max_risk": e["risk"], "event_id": e["id"], "statuses": Counter({e["upstream_status"] or 0: 1}),
                      "evidence": unquote_plus(f"{e['query']} {e['body_snippet'] or ''}").strip()[:90]})
    for s in steps:
        s.pop("_sig")
        s["statuses"] = dict(s["statuses"])
    more = max(0, len(steps) - limit)
    return steps[:limit] + ([{"more": more}] if more else [])


def _fmt(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _recommendations(classes: list[str], outcome: dict, events: list[dict], ip: str, confidence: str, detectors: Counter) -> tuple[list[str], list[dict]]:
    text, actions = [], []
    mon = any(e["action"] == "would_block" for e in events)
    if outcome["level"] == "possibly_succeeded":
        text.append("Treat this as a possible breach: review the application's logs and data for the affected endpoints.")
    if mon and outcome["level"] == "possibly_succeeded":
        text.append("The gateway is in monitor mode, so these requests reached the application. Switch to block mode once false positives are cleared.")
        actions.append({"type": "block_mode", "label": "Switch to block mode"})
    if confidence == "low" and sum(1 for d in LIVE if detectors.get(d)) <= 1:
        text.append("Only one detector fired with modest confidence. If these requests look legitimate, mark them benign; the Learning Inbox will then propose a scoped exemption.")
        actions.append({"type": "review_event", "event_id": events[0]["id"], "label": "Review first request"})
    else:
        actions.insert(0, {"type": "ban", "ip": ip, "label": f"Ban {ip}"})
    for k in classes:
        for f in CATALOG[k]["fix"]:
            if f not in text:
                text.append(f)
    return text, actions


def _narrative(ip: str, events: list[dict], classes: list[dict], detectors: Counter, outcome: dict, severity: str, confidence: str, steps: list[dict]) -> tuple[str, list[str]]:
    first, last = events[0]["ts"], events[-1]["ts"]
    dur = last - first
    span = f"{_fmt(first)} to {_fmt(last)}" if dur >= 1 else f"at {_fmt(first)}"
    names = " + ".join(SHORT[c["key"]] for c in classes[:3])
    summary = f"{ip}: {names} ({len(events)} request{'s' if len(events) != 1 else ''})"
    paths = Counter(template(e["path"]) for e in events)
    p = [f"Client {ip} sent {len(events)} flagged request{'s' if len(events) != 1 else ''} {span}, mostly to {', '.join(f'{k} ({v})' for k, v in paths.most_common(3))}."]
    if len(classes) > 1:
        p.append("The activity covers several techniques, in the order they first appeared: " + " → ".join(c["name"] for c in classes) + ".")
    for c in classes[:3]:
        p.append(f"{c['name']} ({c['events']} request{'s' if c['events'] != 1 else ''}): {CATALOG[c['key']]['what']}")
        ex = next((s["evidence"] for s in steps if "evidence" in s and c["key"] in s["classes"] and s["evidence"]), "")
        if ex:
            p[-1] += f" Example: “{ex}”."
    fired = [d for d in LIVE if detectors.get(d)]
    p.append(f"Detected by {', '.join(fired) or 'the fused score'}; {len(fired)} independent detector{'s' if len(fired) != 1 else ''} agreed, so confidence is {confidence}.")
    p.append(f"Outcome: {outcome['detail']}")
    return summary, p


def build_incident(ip: str, events: list[dict], context: list[dict] | None = None) -> dict:
    """events: flagged events of ONE client, in time order."""
    for e in events:
        e["_classes"] = classify(e)
    cls_events, first_seen = Counter(), {}
    for e in events:
        for k in e["_classes"]:
            cls_events[k] += 1
            first_seen.setdefault(k, e["ts"])
    keys = sorted(cls_events, key=first_seen.get)
    classes = [{"key": k, "name": CATALOG[k]["name"], "events": cls_events[k], "first_ts": first_seen[k],
                "refs": {r: CATALOG[k][r] for r in ("owasp_api", "owasp_top10", "cwe", "attack") if CATALOG[k][r]}} for k in keys]
    detectors = Counter(r["detector"] for e in events for r in e["reasons"] if r["strength"] >= .3 and r["detector"] in LIVE)
    max_risk = max(e["risk"] for e in events)
    outcome = _outcome(events, keys, context or [])
    severity, score = _severity(keys, max_risk, outcome, len(events))
    confidence = _confidence(detectors, max_risk)
    steps = _timeline(events)
    summary, narrative = _narrative(ip, events, classes, detectors, outcome, severity, confidence, steps)
    advice, actions = _recommendations(keys, outcome, events, ip, confidence, detectors)
    refs: dict[str, list] = {}
    for c in classes:
        for r, v in c["refs"].items():
            refs.setdefault(r, [])
            v not in refs[r] and refs[r].append(v)
    for e in events:
        e.pop("_classes", None)                      # scratch key, do not leak into the caller's events
    return {"id": events[0]["id"], "client_ip": ip, "first_ts": events[0]["ts"], "last_ts": events[-1]["ts"], "duration_s": round(events[-1]["ts"] - events[0]["ts"], 1),
            "events": len(events), "requests": len(context) if context else len(events), "max_risk": round(max_risk, 3),
            "avg_risk": round(sum(e["risk"] for e in events) / len(events), 3), "statuses": _statuses(events),
            "blocked": sum(e["action"] == "blocked" for e in events), "would_block": sum(e["action"] == "would_block" for e in events),
            "classes": classes, "detectors": dict(detectors), "paths": Counter(template(e["path"]) for e in events).most_common(5),
            "outcome": outcome, "severity": severity, "score": score, "confidence": confidence, "refs": refs,
            "timeline": steps, "summary": summary, "narrative": narrative, "recommendations": advice, "actions": actions,
            "source": "rules"}


def group(events: list[dict], gap_s: float = GAP_S) -> list[list[dict]]:
    """Split flagged events into per-client runs separated by more than gap_s of quiet."""
    by_ip: dict[str, list] = {}
    for e in sorted(events, key=lambda e: e["ts"]):
        by_ip.setdefault(e["client_ip"], []).append(e)
    runs = []
    for evs in by_ip.values():
        run = [evs[0]]
        for e in evs[1:]:
            if e["ts"] - run[-1]["ts"] > gap_s:
                runs.append(run)
                run = []
            run.append(e)
        runs.append(run)
    return runs


def build_all(events: list[dict], gap_s: float = GAP_S, context=None, limit: int = 200) -> list[dict]:
    """Incidents for a set of flagged events, most severe first. context(ip, first_ts, last_ts) -> that client's events (optional)."""
    out = []
    for run in group([e for e in events if e["action"] in FLAGGED], gap_s):
        ctx = context(run[0]["client_ip"], run[0]["ts"], run[-1]["ts"] + gap_s) if context else None
        out.append(build_incident(run[0]["client_ip"], run, ctx))
    out.sort(key=lambda i: (-SEVERITIES.index(i["severity"]), -i["score"], -i["last_ts"]))
    return out[:limit]
