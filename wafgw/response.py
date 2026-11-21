"""Response protection: look at what the application sends BACK and flag leaks.

Request-side detectors cannot see a stack trace, a SQL error, a private key or a card number leaving the
site. This module scans text/JSON responses (bounded, see `max_inspect_bytes`) and returns findings
{kind, detail, strength}; strengths combine with the same noisy-OR as the request detectors and are
logged as the `response` reason of the event. They never change the request-side verdict or risk.
"""
import re
import statistics
from collections import defaultdict, deque

REDACTED = "[redacted]"

# (kind, regex, strength, redact). Strengths are fixed policy, not tuned: 0.5 alerts on its own.
RULES = [
    ("stack_trace", re.compile(r"Traceback \(most recent call last\)|\n\s+at [\w$.<>]+\([\w$.]+\.java:\d+\)|"
                               r"Stack trace:\s*#0 |\bat (?:Object|Module|Function)\.<anonymous> \(|"
                               r"System\.\w+Exception: |\n\s+at [\w.]+ in [\w:\\/.]+:line \d+"), 0.8, False),
    ("sql_error", re.compile(r"SQLSTATE\[|You have an error in your SQL syntax|sqlite3\.\w*Error|\bORA-\d{5}\b|"
                             r"\bPG::\w+|psycopg2\.\w+|Unclosed quotation mark|unrecognized token|"
                             r"near \"[^\"]{0,40}\": syntax error|database error|mysqli?_\w+\(\)|SQL syntax[^\n]{0,200}MySQL", re.I), 0.7, False),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*-----|$)"), 1.0, True),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.9, True),
    ("jwt", re.compile(r"\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}\b"), 0.6, True),
    ("secret_field", re.compile(r"""(?i)("?(?:password|passwd|pwd|secret|api[_-]?key|private[_-]?key|client[_-]?secret)"?\s*[:=]\s*)"""
                                r"""("[^"\\]{6,}"|'[^'\\]{6,}'|[^\s&,"'}<]{6,})"""), 0.6, True),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.6, True),
    ("directory_listing", re.compile(r"<title>Index of /|<h1>Index of /|\bParent Directory\b"), 0.6, False),
    ("debug_banner", re.compile(r"Werkzeug Debugger|Whoops, looks like something went wrong|phpinfo\(\)|<title>phpinfo|"
                                r"DEBUG = True|Server Error in '/' Application|Fatal error:|Warning: [\w()]+\(\) expects|"
                                r"Django[^\n]{0,100}DEBUG|Laravel[^\n]{0,100}Ignition"), 0.6, False),
]
# Cheap substring gate per rule (lower-case text): the regex only runs when one of these is present. Keeps a 256 KB scan at a few ms.
PRE = {"stack_trace": ("traceback", "stack trace", ".java:", "<anonymous>", "exception: ", ":line "),
       "sql_error": ("sqlstate", "error in your sql", "sqlite3", "ora-", "pg::", "psycopg2", "unclosed quotation", "unrecognized token",
                     "syntax error", "database error", "mysql", "sql syntax"),
       "private_key": ("private key",), "aws_key": ("akia", "asia"), "jwt": ("eyj",),
       "secret_field": ("password", "passwd", "pwd", "secret", "api_key", "api-key", "apikey", "private_key", "private-key"),
       "directory_listing": ("index of /", "parent directory"),
       "debug_banner": ("debugger", "whoops", "phpinfo", "debug = true", "server error in", "fatal error:", "expects", "django", "laravel")}
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,63}")     # bounded: no quadratic scan on long words
BULK_EMAILS = 5
SIZE_FACTOR, SIZE_MIN_SAMPLES, SIZE_FLOOR = 8, 20, 16384


def luhn(digits: str) -> bool:
    nums = [int(c) for c in digits][::-1]
    return len(nums) >= 13 and (sum(nums[0::2]) + sum(sum(divmod(2 * d, 10)) for d in nums[1::2])) % 10 == 0


def iban_ok(raw: str) -> bool:
    """ISO 13616 mod-97 check, so random upper-case codes are not reported as bank accounts."""
    s = raw.replace(" ", "")
    return 15 <= len(s) <= 34 and int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def scan(text: str) -> list[dict]:
    """Findings for one response body: [{kind, detail, strength}]."""
    found, low = [], text.lower()
    for kind, rx, strength, _ in RULES:
        if kind in PRE and not any(k in low for k in PRE[kind]):
            continue
        m = rx.search(text)
        if m:
            found.append({"kind": kind, "detail": f"first at byte {m.start()}", "strength": strength})
    cards = [m.group() for m in _CARD.finditer(text) if luhn(re.sub(r"\D", "", m.group()))]
    if cards:
        found.append({"kind": "card_number", "detail": f"{len(cards)} Luhn-valid number(s)", "strength": 0.7})
    ibans = [m.group() for m in _IBAN.finditer(text) if iban_ok(m.group())]
    if ibans:
        found.append({"kind": "iban", "detail": f"{len(ibans)} valid IBAN(s)", "strength": 0.5})
    emails = set(_EMAIL.findall(text)) if text.count("@") >= BULK_EMAILS else ()
    if len(emails) >= BULK_EMAILS:
        found.append({"kind": "bulk_emails", "detail": f"{len(emails)} distinct e-mail addresses", "strength": 0.5})
    return found


def redact(text: str, found: list[dict]) -> str:
    """Replace what the redactable findings matched (keeps the response shape: keys stay, values go)."""
    kinds = {f["kind"] for f in found}
    for kind, rx, _, can in RULES:
        if can and kind in kinds:
            text = rx.sub(lambda m: (m.group(1) + f'"{REDACTED}"') if m.lastindex and m.lastindex >= 2 else REDACTED, text)
    if "iban" in kinds:
        text = _IBAN.sub(lambda m: REDACTED if iban_ok(m.group()) else m.group(), text)
    if "card_number" in kinds:
        text = _CARD.sub(lambda m: REDACTED if luhn(re.sub(r"\D", "", m.group())) else m.group(), text)
    return text


def strength(found: list[dict]) -> float:
    """Noisy-OR of the findings' strengths."""
    left = 1.0
    for f in found:
        left *= 1 - f["strength"]
    return round(1 - left, 4)


class SizeWatch:
    """Per-route running median of response sizes: one response far bigger than usual is a data-dump signal."""

    def __init__(self, keep: int = 50):
        self.sizes = defaultdict(lambda: deque(maxlen=keep))

    def check(self, path: str, size: int) -> dict | None:
        route = re.sub(r"/\d+", "/{id}", path)
        seen = self.sizes[route]
        flag = None
        if len(seen) >= SIZE_MIN_SAMPLES:
            median = statistics.median(seen)
            if size > max(SIZE_FACTOR * median, median + SIZE_FLOOR):
                flag = {"kind": "size_anomaly", "detail": f"{size} bytes vs median {int(median)} on {route}", "strength": 0.4}
        seen.append(size)
        if len(self.sizes) > 5000:
            self.sizes.clear()
        return flag
