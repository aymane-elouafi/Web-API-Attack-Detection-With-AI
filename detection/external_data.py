"""Real-world labeled data (downloaded into data/external/, see data/external/SOURCES.md) in the
project's request shape: method, path, query, body (+ label, attack_type, source, group).

Anti-leakage rules used everywhere:
  * only path / query / body values are kept -- never Host, User-Agent, Content-Type or cookies;
  * bare payload strings and bare benign strings are put into the SAME three carriers (a search
    parameter, a file-name parameter, a JSON comment), picked by a hash of the text, so the file
    format of a source cannot be learned;
  * everything is normalised and de-duplicated across ALL sources before any split, and the
    training set is purged of anything that also appears in the held-out CSIC 2010 set.
"""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import pandas as pd

from traffic.payloads import BENIGN_TEXT

EXT = Path("data/external")
COLS = ["method", "path", "query", "body", "label", "attack_type", "source", "group"]
MAX_LEN = 2000
_KINDS = [
    ("xss", r"<\s*script|javascript:|\bon\w+\s*=|<\s*(img|svg|iframe|body|video|a)\b|alert\(|document\.cookie|&lt;"),
    ("sqli", r"union\s+(all\s+)?select|['\"]\s*(or|and)\b|\bor\s+['\"\d]|select\s.+\sfrom|sleep\(|benchmark\(|waitfor|"
             r"\bdrop\s+table|order\s+by\s+\d|'\s*--|;\s*(drop|insert|update|delete)\b"),
    ("path_traversal", r"\.\.[/\\]|%2e%2e|/etc/|c:\\|\\windows|boot\.ini|win\.ini|/proc/"),
    ("cmdi", r"[;|&`]\s*(ls|cat|id|whoami|sleep|ping|wget|curl|nc|echo|uname)\b|\$\(|`.+`"),
]
_KINDS = [(k, re.compile(p, re.I)) for k, p in _KINDS]


def classify(text: str) -> str:
    """Best-effort attack class from the text itself (for reporting only, never a feature)."""
    t = unquote(unquote(text))
    return next((k for k, rx in _KINDS if rx.search(t)), "other")


def carry(value: str) -> tuple[str, str, str, str]:
    """Wrap a bare string in one of three request shapes, chosen by hash (same for every class)."""
    h = int(hashlib.md5(value.encode("utf-8", "replace")).hexdigest(), 16) % 3
    if h == 0:
        return "GET", "/search", "q=" + quote(value, safe=""), ""
    if h == 1:
        return "GET", "/files", "name=" + quote(value, safe=""), ""
    return "POST", "/comments", "", json.dumps({"text": value})


def _split_url(line: str) -> tuple[str, str, str, str]:
    """'/a/b?x=1' -> GET path+query as is; anything else is a bare string."""
    if line.startswith("/"):
        path, _, query = line.partition("?")
        return "GET", path, query, ""
    return carry(line)


def _rows(shapes, label, attack_type, source, group) -> list[dict]:
    """shapes: iterable of (method, path, query, body[, attack_type override])."""
    out = []
    for s in shapes:
        kind = s[4] if len(s) > 4 else attack_type
        if len(s[1]) + len(s[2]) + len(s[3]) <= MAX_LEN:
            g = group(s) if callable(group) else group
            out.append(dict(method=s[0], path=s[1], query=s[2], body=s[3], label=label,
                            attack_type=kind, source=source, group=g))
    return out


def _bucket(text: str, n: int = 25) -> str:
    return str(int(hashlib.md5(text.encode("utf-8", "replace")).hexdigest(), 16) % n)


def _lines(path: Path) -> list[str]:
    return [l.rstrip("\r\n") for l in path.read_text("utf-8", "replace").split("\n") if l.strip()]


# --- FWAF -----------------------------------------------------------------------------------
# goodqueries.txt is NOT clean: it holds scanner probes (remote-include URLs, cmd=ls ...).
# Only lines without URL schemes or shell/SQL/HTML metacharacters are used as benign. This makes
# the benign side blunt (little punctuation), which is why punctuation-heavy benign text is added
# separately and measured on the held-out CSIC normals.
_DIRTY = re.compile(r"http|ftp:|cmd=|exec|\\x|['\"<>;|`$]|\.\.|%27|%22|%3c|%3e|%3b|union|select|script|--|\bor\b|\band\b", re.I)


def load_fwaf(n_benign_paths: int = 20000, seed: int = 0) -> pd.DataFrame:
    bad = _lines(EXT / "fwaf/badqueries.txt")
    good = _lines(EXT / "fwaf/goodqueries.txt")
    shapes = [_split_url(l.replace("XXpathXX", "http://evil.example/x.txt")) for l in bad]   # placeholder = leak
    rows = _rows([s + (classify(s[2] or s[1] or s[3]),) for s in shapes], 1, "other", "fwaf_bad",
                 lambda s: _bucket("/".join(s[1].split("/")[:3])))
    clean = [l for l in good if not _DIRTY.search(l)]
    with_q = [l for l in clean if "?" in l]
    without_q = pd.Series([l for l in clean if "?" not in l]).sample(n_benign_paths, random_state=seed).tolist()
    # half of the bare benign paths are carried like bare payloads (search/file/comment shapes)
    shapes = [_split_url(l) if "?" in l or int(_bucket(l, 2)) else carry(l.strip("/").replace("/", " ")) for l in with_q + without_q]
    rows += _rows(shapes, 0, "normal", "fwaf_good", lambda s: _bucket(s[1] + s[2]))
    return pd.DataFrame(rows, columns=COLS)


# --- payload corpora ------------------------------------------------------------------------
LISTS = {  # glob under data/external -> attack class
    "patt/SQL Injection/Intruder/*.txt": "sqli",
    "patt/XSS Injection/Intruders/*.txt": "xss",
    "seclists/Fuzzing/XSS/*/*.txt": "xss",
    "seclists/Fuzzing/URI-XSS.fuzzdb.txt": "xss",
    "seclists/Fuzzing/LFI/*.txt": "path_traversal",
    "seclists/Fuzzing/command-injection-commix.txt": "cmdi",
}
_MD = {"patt/Directory Traversal/README.md": ("path_traversal", re.compile(r"\.\.[/\\]|%2e%2e|/etc/|\\windows", re.I)),
       "patt/Command Injection/README.md": ("cmdi", re.compile(r"[;|&`]|\$\("))}
PER_FILE_CAP = 3000


def _fenced(path: Path) -> list[str]:
    out, inside = [], False
    for l in path.read_text("utf-8", "replace").split("\n"):
        if l.startswith("```"):
            inside = not inside
        elif inside and 3 <= len(l.strip()) <= 200 and not l.lstrip().startswith(("#", "//")):
            out.append(l.strip())
    return out


def load_payload_lists(seed: int = 0) -> pd.DataFrame:
    rows = []
    for pattern, kind in LISTS.items():
        for f in sorted(EXT.glob(pattern)):
            vals = [l.strip() for l in _lines(f) if not l.startswith("#")]
            vals = pd.Series(sorted(set(vals))).sample(min(PER_FILE_CAP, len(set(vals))), random_state=seed).tolist() if vals else []
            rows += _rows([carry(v) for v in vals], 1, kind, "payload_lists", f.name)
    for rel, (kind, rx) in _MD.items():
        if (EXT / rel).exists():
            rows += _rows([carry(v) for v in _fenced(EXT / rel) if rx.search(v)], 1, kind, "payload_lists", rel)
    return pd.DataFrame(rows, columns=COLS)


# --- OWASP CRS regression tests (no PyYAML here, so a small text parser) ------------------------
_CRS_KIND = {"941": "xss", "942": "sqli", "930": "path_traversal", "932": "cmdi"}


def _unq(v: str) -> str:
    v = v.strip()
    if v[:1] == '"':
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v.strip('"')
    return v.strip("'")


def load_crs() -> pd.DataFrame:
    rows = []
    for f in sorted((EXT / "crs/tests/regression/tests").rglob("*.yaml")):
        text = f.read_text("utf-8", "replace")
        m = re.search(r"^rule_id:\s*(\d+)", text, re.M)
        kind = _CRS_KIND.get(m.group(1)[:3], "other") if m else "other"
        for block in re.split(r"^\s*- test_id:", text, flags=re.M)[1:]:
            uri = re.search(r"^\s*uri:\s*(.+)$", block, re.M)
            data = re.search(r"^\s*data:\s*(.+)$", block, re.M)
            positive = "no_expect_ids" not in block and "expect_ids" in block
            negative = "no_expect_ids" in block
            if not uri or not (positive or negative):
                continue
            path, _, query = _unq(uri.group(1)).partition("?")
            body = _unq(data.group(1)) if data else ""
            rows += _rows([("GET" if not body else "POST", path, query, body)], int(positive),
                          kind if positive else "normal", "crs_tests", f.name)
    return pd.DataFrame(rows, columns=COLS)


# --- CSIC 2010 (held out entirely; never used for training) -------------------------------------
def load_csic() -> pd.DataFrame:
    d = pd.read_csv(EXT / "csic2010/csic_2010_processed.csv", usecols=["method", "url", "payload", "label"], keep_default_na=False)
    rows = []
    for r in d.itertuples(index=False):
        u = urlsplit(r.url)
        query = "&".join(x for x in (u.query, r.payload) if x)    # GET payload = query, POST payload = form body
        attack = r.label == "anom"
        rows += _rows([(r.method, u.path, query, "")], int(attack), classify(u.path + "?" + query) if attack else "normal", "csic2010", "csic")
    return pd.DataFrame(rows, columns=COLS)


# --- the project's own synthetic data -------------------------------------------------------
def load_synthetic(path: str = "data/dataset.csv") -> pd.DataFrame:
    from detection.ml_payload import TRAIN_ATTACKS
    d = pd.read_csv(path, keep_default_na=False)
    d = d[d.attack_type.isin(TRAIN_ATTACKS | {"normal"})]
    rows = [dict(method=r.method, path=r.path, query=r.query, body=r.body, label=r.label, attack_type=r.attack_type,
                 source="synthetic", group=r.client_ip) for r in d.itertuples(index=False)]
    from urllib.parse import quote as q
    for t in BENIGN_TEXT:
        rows.append(dict(method="GET", path="/products/search", query="q=" + q(t, safe=""), body="", label=0,
                         attack_type="normal", source="benign_text", group="benign_text"))
        rows.append(dict(method="POST", path="/comments", query="", body=json.dumps({"text": t}), label=0,
                         attack_type="normal", source="benign_text", group="benign_text"))
    return pd.DataFrame(rows, columns=COLS)


# --- generated harmless text with punctuation and SQL/HTML-looking words -----------------------------------
# No approved source has benign text with quotes, dashes and words like "select" / "union" / "drop", and
# FWAF's benign side had to be filtered of all punctuation, so such sentences are generated from word lists.
_WORDS = dict(
    who=["O'Brien", "D'Angelo", "McDonald's", "Levi's", "women's", "men's", "kids'", "Jane's", "the team's"],
    item=["laptop", "keyboard", "charger", "backpack", "headphones", "monitor", "desk lamp", "water bottle", "sneakers", "tent"],
    sql=["select", "union", "drop", "order", "insert", "update", "delete", "from", "where", "and", "or", "table", "like"],
    glue=[" -- ", " - ", " & ", ", ", "; ", ": ", " / ", " > ", " < ", " (", " + ", " = ", " | ", " ~ "],
    tail=["", "!", "?", ".", " :)", " <3", " 100%", ")", " (new)", " #1", " @home", " $9.99"],
)


def load_benign_generated(n: int = 4000, seed: int = 0) -> pd.DataFrame:
    import random
    r = random.Random(seed)
    w = _WORDS
    texts = set()
    while len(texts) < n:
        t = r.choice([
            f"{r.choice(w['who'])} {r.choice(w['item'])}{r.choice(w['glue'])}{r.choice(w['sql'])} {r.choice(w['item'])}{r.choice(w['tail'])}",
            f"{r.choice(w['sql'])} a {r.choice(w['item'])}{r.choice(w['glue'])}{r.choice(w['who'])} {r.choice(w['sql'])}{r.choice(w['tail'])}",
            f"{r.choice(w['item'])}{r.choice(w['glue'])}{r.choice(w['item'])}{r.choice(w['glue'])}size {r.randint(1, 50)}{r.choice(w['tail'])}",
            f"{r.randint(5, 90)}% off {r.choice(w['item'])}{r.choice(w['glue'])}{r.choice(w['sql'])} {r.choice(w['who'])} {r.choice(w['item'])}",
        ])
        texts.add(t)
    return pd.DataFrame(_rows([carry(t) for t in sorted(texts)], 0, "normal", "benign_gen", lambda s: _bucket(s[1] + s[2], 10)), columns=COLS)


# --- normalise + de-duplicate ---------------------------------------------------------------------
def key(df: pd.DataFrame) -> pd.Series:
    """Request identity after URL-decoding twice, lower-casing and squeezing whitespace."""
    sq = lambda s: re.sub(r"\s+", " ", unquote(unquote(s))).strip().lower()
    return df.method + "|" + df.path.map(sq) + "|" + df["query"].map(sq) + "|" + df.body.map(sq)


def dedupe(df: pd.DataFrame, drop: pd.Series | None = None) -> pd.DataFrame:
    """Drop exact duplicates; drop keys seen with both labels; optionally drop keys in `drop`."""
    k = key(df)
    conflicted = k[df.assign(_k=k).groupby("_k").label.transform("nunique") > 1]
    out = df[~k.isin(set(conflicted)) & ~k.duplicated()]
    return out[~key(out).isin(set(drop))] if drop is not None else out


def load_all() -> tuple[pd.DataFrame, pd.DataFrame]:
    """(training set, CSIC 2010 test set). Training is purged of anything that is also in CSIC."""
    csic = dedupe(load_csic())
    train = pd.concat([load_synthetic(), load_benign_generated(), load_fwaf(), load_payload_lists(), load_crs()], ignore_index=True)
    return dedupe(train, drop=key(csic)).reset_index(drop=True), csic.reset_index(drop=True)
