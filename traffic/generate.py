"""Traffic generator: simulates normal users and attackers against the demo API
and writes a labeled dataset to data/dataset.csv.

Usage (the API must be running first):
    python -m traffic.generate --seed 42 --scale 1.0

How it works
  1. PLAN   -- build every request first, each with a *simulated* timestamp
               (a 24h "day"), so we get realistic request rates without waiting.
  2. SEND   -- send the planned requests, in time order, to the real API.
  3. SAVE   -- record what the server answered next to the ground-truth label.

Labels: label=1 means "this request is part of an attack attempt" (even if the
attack failed). attack_type / variant describe which attack and which evasion
trick. Harmless requests that merely *look* suspicious (an apostrophe in a
search, the word "select" in a comment, a busy shopper...) are labeled 0 on
purpose: they are the hard cases for the detector.

User agents: normal users use browsers, the mobile app or the odd script. Most
attackers also use ordinary-looking agents (a careful attacker changes the header);
only ~12% of sqli / traversal / brute-force sessions are noisy tools (sqlmap, Nikto,
Hydra) with their default agent -- and in those sessions EVERY request is an attack.

NOTE for later: client_ip, user_agent, attack_type and variant must NOT be used
as ML features -- client_ip is only for grouping requests per client, and the user
agent is trivially spoofed.
"""
import argparse
import csv
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import httpx

from common import seed as S
from traffic import payloads as P

DAY = 86_400  # simulated seconds covered by the dataset

BROWSER_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
APP_UAS = ["MyShop/2.3 (iOS 17.4)", "MyShop/2.3 (Android 14)", "okhttp/4.12.0"]
SCRIPT_UAS = ["python-requests/2.31.0", "curl/8.5.0", "PostmanRuntime/7.36.0"]

NORMAL_FILES = ["readme.txt", "terms.txt", "logo.txt"]
NORMAL_COMMENTS = [
    "Great product, fast delivery!",
    "Works as described :)",
    "I love it <3",
    "Is 5 > 3 stars fair? Maybe 4.",
    "Q&A: does it support USB-C?",
    "Arrived late, but support was great.",
    "100% recommended",
    "It's the best one I've owned.",
    "Price went from $120 to $99 -- nice deal",
    "Can someone explain the difference, select the right model or the union of both features?",
    "Would I buy it again? OR maybe wait for the next version.",
    "Perfect for work (and games).",
]
SCANNER_SHARE = 0.12   # share of sqli / traversal / brute-force sessions run by a noisy default-UA tool


# --------------------------------------------------------------------------- #
# PLAN
# --------------------------------------------------------------------------- #
class Plan:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.steps: list[dict] = []
        self.n_sessions = 0
        self.user_ips = {i: f"10.0.{i // 250}.{i % 250 + 2}" for i in range(1, S.N_USERS + 1)}

    def new_session_id(self) -> str:
        self.n_sessions += 1
        return f"s{self.n_sessions}"

    def external_ip(self) -> str:
        r = self.rng
        return (f"{r.choice([45, 77, 91, 103, 185, 194, 203])}."
                f"{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}")

    def user_agent(self) -> str:
        r = self.rng
        pool = r.choices([BROWSER_UAS, APP_UAS, SCRIPT_UAS], [70, 25, 5])[0]
        return r.choice(pool)

    def attacker_ua(self) -> str:
        """Ordinary-looking user agent (browser / script / spoofed app) -- no tool give-away."""
        r = self.rng
        pool = r.choices([BROWSER_UAS, SCRIPT_UAS, APP_UAS], [50, 40, 10])[0]
        return r.choice(pool)


class Session:
    """One client doing things over time; every .req() adds one planned request."""

    def __init__(self, plan: Plan, ip: str, ua: str, t0: float):
        self.plan, self.ip, self.ua, self.t = plan, ip, ua, t0
        self.id = plan.new_session_id()

    def wait(self, lo: float, hi: float) -> None:
        self.t += self.plan.rng.uniform(lo, hi)

    def req(self, method, path, *, query="", body=None, auth=True,
            label=0, kind="normal", variant="none", action=None) -> None:
        self.plan.steps.append({
            "session": self.id, "ts": self.t, "ip": self.ip, "ua": self.ua,
            "method": method, "path": path, "query": query, "body": body,
            "auth": auth, "label": label, "kind": kind, "variant": variant,
            "action": action,
        })

    def login(self, username, password, **kw) -> None:
        self.req("POST", "/login", body={"username": username, "password": password},
                 auth=False, action="login", **kw)


def normal_search(r: random.Random) -> str:
    w = r.choice(S.PRODUCT_WORDS)
    x = r.random()
    if x < 0.55:
        return w
    if x < 0.75:
        return f"{w} {r.choice(S.COLORS)}"
    if x < 0.85:
        return f"usb-c {w}"
    if x < 0.90:
        return f"{w} & accessories"
    if x < 0.95:
        return f"men's {w}"        # apostrophe: harmless, but looks like SQLi
    return f"{w} 50% off"


def search_query(term: str) -> str:
    return "q=" + quote(term, safe="")


# ----- normal behaviour -------------------------------------------------------
def normal_session(plan: Plan, i: int, t0: float) -> None:
    r = plan.rng
    s = Session(plan, plan.user_ips[i], plan.user_agent(), t0)
    uid = S.user_id(i)
    busy = r.random() < 0.08                    # a "busy shopper" browses fast
    gap = (0.3, 1.5) if busy else (2, 25)

    if r.random() < 0.12:                       # typo in the password first
        s.login(S.username(i), S.password(i)[:-1])
        s.wait(2, 6)
    s.login(S.username(i), S.password(i))

    for _ in range(r.randint(6, 25)):
        s.wait(*gap)
        a = r.choices(
            ["search", "product", "orders", "order", "me", "update", "comments", "comment", "file"],
            [35, 20, 8, 10, 8, 4, 6, 5, 4])[0]
        if a == "search":
            s.req("GET", "/products/search", query=search_query(normal_search(r)))
        elif a == "product":
            s.req("GET", f"/products/{r.randint(1, S.n_products())}")
        elif a == "orders":
            s.req("GET", "/orders")
        elif a == "order":
            s.req("GET", f"/orders/{r.choice(S.order_ids_for(uid))}")
        elif a == "me":
            s.req("GET", "/users/me")
        elif a == "update":
            s.req("PUT", "/users/me", body={"email": f"user{i}.{r.randint(1, 99)}@example.com"})
        elif a == "comments":
            s.req("GET", "/comments")
        elif a == "comment":
            s.req("POST", "/comments", body={"text": r.choice(NORMAL_COMMENTS)})
        else:
            s.req("GET", "/files", query="name=" + r.choice(NORMAL_FILES))


# ----- attacks ----------------------------------------------------------------
def sqli_session(plan: Plan, t0: float) -> None:
    r = plan.rng
    tool = r.random() < SCANNER_SHARE           # sqlmap with its default user agent
    s = Session(plan, plan.external_ip(), P.SCANNER_UAS["sqli"] if tool else plan.attacker_ua(), t0)
    gap = (0.2, 1.0) if tool or r.random() < 0.4 else (1.5, 8)
    for _ in range(r.randint(5, 25)):
        s.wait(*gap)
        if not tool and r.random() < 0.25:      # a human blends in with a harmless request; a tool never does
            s.req("GET", "/products/search", query=search_query(normal_search(r)))
        elif r.random() < 0.7:
            val, variant = P.sqli(r, "query")
            s.req("GET", "/products/search", query="q=" + val,
                  label=1, kind="sqli", variant=variant)
        else:
            val, variant = P.sqli(r, "body")
            s.login(val, r.choice(["x", "password", "test"]),
                    label=1, kind="sqli", variant=variant)


def xss_session(plan: Plan, t0: float) -> None:
    r = plan.rng
    i = r.randint(1, S.N_USERS)                 # attacker uses a leaked account
    s = Session(plan, plan.external_ip(), plan.attacker_ua(), t0)
    s.login(S.username(i), S.password(i))
    for _ in range(r.randint(2, 10)):
        s.wait(3, 20)
        if r.random() < 0.3:
            s.req("POST", "/comments", body={"text": r.choice(NORMAL_COMMENTS)})
        else:
            text, variant = P.xss(r)
            s.req("POST", "/comments", body={"text": text},
                  label=1, kind="xss", variant=variant)


def traversal_session(plan: Plan, t0: float) -> None:
    r = plan.rng
    tool = r.random() < SCANNER_SHARE           # Nikto with its default user agent
    s = Session(plan, plan.external_ip(), P.SCANNER_UAS["path_traversal"] if tool else plan.attacker_ua(), t0)
    gap = (0.2, 1.0) if tool or r.random() < 0.4 else (1.5, 8)
    for _ in range(r.randint(4, 12)):
        s.wait(*gap)
        if not tool and r.random() < 0.3:
            s.req("GET", "/files", query="name=" + r.choice(NORMAL_FILES))
        else:
            val, variant = P.traversal(r)
            s.req("GET", "/files", query="name=" + val,
                  label=1, kind="path_traversal", variant=variant)


def mass_assignment_session(plan: Plan, t0: float) -> None:
    r = plan.rng
    i = r.randint(1, S.N_USERS)
    s = Session(plan, plan.user_ips[i], plan.user_agent(), t0)
    s.login(S.username(i), S.password(i))
    for _ in range(r.randint(1, 3)):
        s.wait(2, 15)
        s.req("GET", "/users/me")
    bodies = [
        {"role": "admin"},
        {"email": f"user{i}@example.com", "role": "admin"},
        {"is_admin": True},
        {"role": "admin", "name": "x"},
        {"isAdmin": True, "role": "superuser"},
    ]
    for _ in range(r.randint(1, 4)):
        s.wait(2, 15)
        s.req("PUT", "/users/me", body=r.choice(bodies), label=1, kind="mass_assignment")


def bola_session(plan: Plan, t0: float) -> None:
    """A legitimate user who starts walking through other people's order ids."""
    r = plan.rng
    i = r.randint(1, S.N_USERS)
    s = Session(plan, plan.user_ips[i], plan.user_agent(), t0)
    s.login(S.username(i), S.password(i))
    s.wait(1, 3)
    s.req("GET", "/orders")
    start = r.randint(1, S.n_orders() - 10)
    stride = r.choice([1, 1, 1, 2, 3])
    gap = (0.3, 1.5) if r.random() < 0.7 else (2, 8)
    for k in range(r.randint(20, 60)):
        s.wait(*gap)
        s.req("GET", f"/orders/{start + k * stride}", label=1, kind="bola")


def brute_force_session(plan: Plan, t0: float) -> None:
    r = plan.rng
    tool = r.random() < SCANNER_SHARE           # Hydra with its default user agent
    s = Session(plan, plan.external_ip(), P.SCANNER_UAS["brute_force"] if tool else plan.attacker_ua(), t0)
    stuffing = r.random() < 0.5                 # many accounts vs one account
    slow = r.random() < 0.3                     # "low and slow" evades simple limits
    gap = (5, 20) if slow else (0.1, 0.6)
    n = r.randint(15, 30) if slow else r.randint(25, 80)
    idx = r.randint(0, S.N_USERS)               # 0 = admin
    target = (S.ADMIN_USERNAME, S.ADMIN_PASSWORD) if idx == 0 else (S.username(idx), S.password(idx))
    for _ in range(n):
        s.wait(*gap)
        user = S.username(r.randint(1, S.N_USERS)) if stuffing else target[0]
        s.login(user, r.choice(P.BRUTE_PASSWORDS), label=1, kind="brute_force")
    if r.random() < 0.4:                        # the attack finally succeeds
        s.wait(*gap)
        s.login(*target, label=1, kind="brute_force")


def build_plan(seed: int, scale: float) -> list[dict]:
    rng = random.Random(seed)
    plan = Plan(rng)
    n = lambda base: max(1, round(base * scale))            # noqa: E731
    start = lambda: rng.uniform(0, DAY - 3600)              # noqa: E731

    for i in range(1, S.N_USERS + 1):
        for _ in range(n(5)):
            normal_session(plan, i, start())
    for fn, count in [(sqli_session, 24), (xss_session, 20), (traversal_session, 14),
                      (mass_assignment_session, 25), (bola_session, 8),
                      (brute_force_session, 6)]:
        for _ in range(n(count)):
            fn(plan, start())
    return plan.steps


# --------------------------------------------------------------------------- #
# SEND + SAVE
# --------------------------------------------------------------------------- #
COLUMNS = ["id", "ts", "client_ip", "user", "user_agent", "method", "path", "query", "body",
           "status", "resp_len", "resp_ms", "label", "attack_type", "variant",
           "waf_score", "waf_rules", "waf_block"]   # waf_*: filled only when sent via the Coraza proxy

HOST = "shop.example.test"    # real clients send a hostname, not a bare IP address


def execute(steps: list[dict], base_url: str) -> list[dict]:
    steps.sort(key=lambda s: s["ts"])
    tokens: dict[str, tuple[str, str]] = {}      # session -> (token, username)
    rows = []
    with httpx.Client(base_url=base_url, timeout=15) as http:
        for n, s in enumerate(steps, 1):
            headers = {"User-Agent": s["ua"], "X-Forwarded-For": s["ip"], "Host": HOST}
            user = ""
            if s["auth"] and s["session"] in tokens:
                token, user = tokens[s["session"]]
                headers["Authorization"] = f"Bearer {token}"
            url = s["path"] + ("?" + s["query"] if s["query"] else "")
            t_start = time.perf_counter()
            resp = http.request(s["method"], url, json=s["body"], headers=headers)
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            if s["action"] == "login" and resp.status_code == 200:
                data = resp.json()
                tokens[s["session"]] = (data["token"], data["user"])
            rows.append({
                "id": n, "ts": round(s["ts"], 3), "client_ip": s["ip"], "user": user,
                "user_agent": s["ua"], "method": s["method"], "path": s["path"],
                "query": s["query"], "body": json.dumps(s["body"]) if s["body"] is not None else "",
                "status": resp.status_code, "resp_len": len(resp.content),
                "resp_ms": round(elapsed_ms, 2), "label": s["label"],
                "attack_type": s["kind"], "variant": s["variant"],
                "waf_score": resp.headers.get("x-waf-score", ""),
                "waf_rules": resp.headers.get("x-waf-rules", ""),
                "waf_block": resp.headers.get("x-waf-block", ""),
            })
            if n % 500 == 0:
                print(f"  sent {n}/{len(steps)} requests...")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8000",
                    help="API address; use http://127.0.0.1:8080 to go through the Coraza proxy")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--scale", type=float, default=1.0, help="multiplies the number of sessions")
    ap.add_argument("--out", default="data/dataset.csv")
    args = ap.parse_args()

    try:
        httpx.get(f"{args.url}/health", timeout=5, headers={"Host": HOST}).raise_for_status()
    except httpx.HTTPError:
        sys.exit(f"Cannot reach the API at {args.url}. Start it first:\n"
                 "  uvicorn target_api.app:app --host 127.0.0.1 --port 8000")

    steps = build_plan(args.seed, args.scale)
    print(f"Planned {len(steps)} requests. Sending...")
    rows = execute(steps, args.url)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)

    attacks = sum(r["label"] for r in rows)
    print(f"\nWrote {len(rows)} rows to {out}")
    print(f"  normal: {len(rows) - attacks}   attack: {attacks} ({attacks / len(rows):.0%})")
    for kind, count in sorted(Counter(r["attack_type"] for r in rows if r["label"]).items()):
        print(f"    {kind:16s} {count}")


if __name__ == "__main__":
    main()
