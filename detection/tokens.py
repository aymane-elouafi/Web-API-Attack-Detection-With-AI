"""Parser-style features: turn text into a short sequence of token CLASSES (SQL / HTML / JS / path).

An n-gram model memorises strings it has seen. Token classes capture the STRUCTURE of an injection
instead: `' or 1 = 1 --` becomes `q K:or n = n c`, and so does every variant with other numbers,
spacing or case. This is the idea behind libinjection and semantic WAF engines, kept deliberately small:
one regex pass (a string is NOT matched as a unit: one stray quote would swallow the injection after it), no real SQL/JS grammar.
"""
import re

SQL_WORDS = {"select", "union", "insert", "update", "delete", "drop", "alter", "create", "truncate", "exec", "execute",
             "from", "where", "having", "group", "order", "limit", "offset", "into", "values", "set", "join",
             "or", "and", "not", "null", "like", "in", "is", "between", "exists", "case", "when", "then", "else",
             "sleep", "benchmark", "waitfor", "delay", "pg_sleep", "concat", "char", "chr", "substr", "substring",
             "ascii", "cast", "convert", "load_file", "outfile", "information_schema", "sqlite_master", "version",
             "user", "database", "table", "true", "false", "all", "distinct", "xp_cmdshell"}
JS_WORDS = {"alert", "confirm", "prompt", "eval", "document", "window", "cookie", "fetch", "atob", "settimeout",
            "setinterval", "constructor", "innerhtml", "location", "onerror", "onload"}
TAGS = {"script", "img", "svg", "iframe", "object", "embed", "body", "a", "link", "style", "video", "audio", "math",
        "input", "form", "details", "marquee", "base", "meta", "source"}

_TOKEN = re.compile(r"""
    (?P<com>--|\#|/\*.*?\*/|/\*)                # SQL comment
  | (?P<tag></?\s*[a-z][a-z0-9]*)               # HTML tag start
  | (?P<ev>\bon[a-z]{3,}\s*=)                   # onerror= onload= ...
  | (?P<scheme>\b(?:javascript|data|vbscript|file|php|expect|gopher):)
  | (?P<dots>(?:\.\.[/\\;]|%2e%2e)+)            # path traversal steps
  | (?P<crlf>%0d%0a|%0a|%0d)                    # header / log injection
  | (?P<pct>%[0-9a-f]{2})                       # leftover percent-escape (double encoding)
  | (?P<q>['"`])                                # every quote is a token: a stray one is where an injection breaks out
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<word>[a-z_][a-z0-9_]*)
  | (?P<op><=|>=|<>|!=|\|\||&&|=|<|>|\+|-|\*|/|%|\||&|\^|~|!)
  | (?P<p>[(){}\[\],;:.$@\\?])
""", re.X | re.S)


def tokenize(text: str) -> str:
    """Space-separated token classes. Unknown words collapse to `w`, so the model sees structure, not vocabulary."""
    out = []
    for m in _TOKEN.finditer(text.lower()):
        kind, tok = m.lastgroup, m.group()
        if kind == "word":
            out.append("K:" + tok if tok in SQL_WORDS else "J:" + tok if tok in JS_WORDS else "w")
        elif kind == "tag":
            name = tok.lstrip("</ \t").strip()
            out.append(("T/" if tok.startswith("</") else "T:") + (name if name in TAGS else "x"))
        elif kind == "scheme":
            out.append("S:" + tok[:-1])
        elif kind in ("op", "p"):
            out.append(tok)
        else:
            out.append({"com": "c", "ev": "ev", "dots": "dots", "crlf": "crlf", "pct": "pct", "q": "q", "num": "n"}[kind])
    return " ".join(out)
