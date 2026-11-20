"""API schema detector (positive security): learn what normal requests look like, flag what does not fit.

Text models cannot see structural attacks: an unknown or renamed parameter, a missing field, a value
of the wrong type, a path that does not exist, a privileged field (role, is_admin) slipped into an
update. This module learns, per endpoint (method + path with ids replaced by {id}): the parameters
and JSON body keys, which are required, their value types, lengths, character sets and (for small
closed sets such as button labels) the allowed values. Or it takes them from an OpenAPI 3 spec.

Poisoning guard: a parameter / value / character is only accepted when it was seen at least
`min_support` times and in at least `min_share` of that endpoint's requests, and an endpoint only
with `min_support` requests, so one-off attack traffic in the learning window is not learned.

Policy (fixed up front, not tuned on any test labels): each finding has a strength, findings are
combined with a noisy-OR, and 0.5 means "alert on its own". Hard structural breaks (unknown
endpoint / parameter / method, privileged field, value outside a closed set) are 0.5+; softer
signals (missing field, wrong type, odd characters, long value) are 0.3-0.45, so one alone is a
warning and two together alert.
"""
import json
import re
from collections import Counter, defaultdict
from urllib.parse import parse_qsl

STRENGTH = dict(unknown_endpoint=0.5, method_not_allowed=0.5, unknown_param=0.5, privileged_field=0.6,
                enum_violation=0.5, missing_required=0.4, type_mismatch=0.45, charset_shift=0.3, length_outlier=0.3)
STATIC_EXT = (".gif", ".jpg", ".jpeg", ".png", ".css", ".js", ".ico", ".svg", ".woff", ".woff2", ".map", ".txt", ".pdf")
PRIVILEGED = {"role", "roles", "is_admin", "isadmin", "admin", "is_staff", "is_superuser", "superuser",
              "permissions", "privileges", "scope", "scopes", "owner_id", "user_id", "verified", "is_verified", "balance"}
NEUTRAL_METHODS = {"OPTIONS", "HEAD"}

_SEG_ID = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|\{[^}]*\})$", re.I)
_INT, _FLOAT, _ALNUM = re.compile(r"^-?\d+$"), re.compile(r"^-?\d+\.\d+$"), re.compile(r"^\w+$")
_FITS = {"int": {"int", "float", "alnum", "text"}, "float": {"float", "text"}, "bool": {"bool", "alnum", "text"},
         "alnum": {"alnum", "text"}, "text": {"text"}}
_MAX_DISTINCT = 200          # distinct values remembered per parameter while learning


def template(path: str) -> str:
    """/orders/17 -> /orders/{id}  (numbers, UUIDs, long hex ids). Trailing slash and case are kept on purpose."""
    return "/".join("{id}" if _SEG_ID.match(s) else s for s in path.split("/"))


def vtype(v) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if v is None:
        return "null"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "object"
    s = str(v)
    if s == "":
        return "empty"
    if s.lower() in ("true", "false"):
        return "bool"
    return "int" if _INT.match(s) else "float" if _FLOAT.match(s) else "alnum" if _ALNUM.match(s) else "text"


def fits(t: str, accepted) -> bool:
    return t == "empty" or t in accepted or bool(_FITS.get(t, set()) & set(accepted))


def symbols(s: str) -> set[str]:
    """Character classes (digit, lower, upper, space, non-ascii letter) and each punctuation char itself."""
    out = set()
    for c in s:
        out.add("d" if c.isdigit() else "l" if "a" <= c <= "z" else "u" if "A" <= c <= "Z" else "s" if c == " "
                else "a" if c.isalpha() else c)
    return out


def extract(query: str, body: str) -> dict[str, list]:
    """name -> values, from the query string and the body (JSON object, nested one level; or form fields)."""
    out: dict[str, list] = defaultdict(list)
    for k, v in parse_qsl(query, keep_blank_values=True):
        out[k].append(v)
    if body:
        try:
            obj = json.loads(body)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            for k, v in obj.items():
                out[k].append(v)
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        out[f"{k}.{k2}"].append(v2)
        elif obj is None and "=" in body:
            for k, v in parse_qsl(body, keep_blank_values=True):
                out[k].append(v)
        else:
            out["(body)"].append(body)
    return out


class _Raw:
    """Counters for one parameter of one endpoint, while learning."""

    def __init__(self):
        self.n = 0
        self.types, self.lens, self.syms, self.values = Counter(), Counter(), Counter(), Counter()

    def add(self, v) -> None:
        self.n += 1
        self.types[vtype(v)] += 1
        if isinstance(v, (dict, list)):
            return
        s = str(v)
        self.lens[len(s)] += 1
        self.syms.update(symbols(s))
        if len(self.values) < _MAX_DISTINCT or s in self.values:
            self.values[s] += 1


class SchemaModel:
    def __init__(self, min_support: int = 5, min_share: float = 0.005):
        self.min_support, self.min_share = min_support, min_share
        self.endpoints: dict[str, dict] = {}     # template -> {"methods": {METHOD: {"n", "open", "params": {...}}}}
        self._raw: dict = {}                     # (template, METHOD) -> [n, {param: _Raw}]

    # --- learning -----------------------------------------------------------------------------------
    def learn(self, requests) -> "SchemaModel":
        """requests: iterable of (method, path, query, body). Can be called several times."""
        for method, path, query, body in requests:
            n_params = self._raw.setdefault((template(path), method.upper()), [0, defaultdict(_Raw)])
            n_params[0] += 1
            for name, values in extract(query, body).items():
                for v in values:
                    n_params[1][name].add(v)
        return self._finalize()

    def _finalize(self) -> "SchemaModel":
        self.endpoints = {}
        support = self.min_support
        for (tpl, method), (n, params) in self._raw.items():
            if n < support:
                continue
            accepted = {}
            for name, raw in params.items():
                if raw.n < support or raw.n < self.min_share * n:
                    continue
                accepted[name] = self._profile(raw, n)
            self.endpoints.setdefault(tpl, {"methods": {}})["methods"][method] = {"n": n, "open": False, "params": accepted}
        return self

    def _profile(self, raw: _Raw, n_endpoint: int) -> dict:
        opaque = raw.values.get("***", 0) >= 0.9 * raw.n      # redacted secrets in gateway events: names only
        min_count = max(self.min_support, self.min_share * raw.n)
        types = sorted(t for t, c in raw.types.items() if c >= min_count and t != "empty") or ["text"]
        lens = sorted(raw.lens.elements())
        max_len = lens[min(len(lens) - 1, int(0.98 * len(lens)))] if lens else 0
        syms = "".join(sorted(s for s, c in raw.syms.items() if c >= min_count))
        good = {v for v, c in raw.values.items() if c >= 2}
        closed = (raw.n >= 20 and 0 < len(good) <= 12 and sum(raw.values[v] for v in good) >= 0.98 * raw.n
                  and not set(types) <= {"int", "float"})
        return {"n": raw.n, "required": raw.n >= 0.95 * n_endpoint and n_endpoint >= self.min_support,
                "types": types, "max_len": max_len, "symbols": syms, "enum": sorted(good) if closed else None,
                "opaque": opaque}

    # --- scoring --------------------------------------------------------------------------------------
    def score(self, method: str, path: str, query: str = "", body: str = "") -> list[dict]:
        """Findings [{kind, param, detail, strength}], strongest first. Empty = fits the schema."""
        method, tpl = method.upper(), template(path)
        ep = self.endpoints.get(tpl)
        if ep is None:
            weak = path.lower().endswith(STATIC_EXT)
            return [self._f("unknown_endpoint", "", f"{tpl} was never seen", 0.5 / 2 if weak else None)]
        if method in NEUTRAL_METHODS:
            return []
        spec = ep["methods"].get(method)
        if spec is None:
            return [self._f("method_not_allowed", "", f"{method} is not used on {tpl} (only {', '.join(sorted(ep['methods']))})")]
        out, seen = [], extract(query, body)
        params = spec["params"]
        for name, values in seen.items():
            p = params.get(name)
            if p is None:
                priv = name.split(".")[-1].lower() in PRIVILEGED
                if priv or not spec["open"]:     # an open body (spec without properties) tolerates unknown keys, never privileged ones
                    out.append(self._f("privileged_field" if priv else "unknown_param", name,
                                       f"'{name}' is not a known field of {method} {tpl}"))
                continue
            for v in values:
                out += self._check_value(name, v, p)
        out += [self._f("missing_required", name, f"'{name}' is always sent to {method} {tpl} but is missing")
                for name, p in params.items() if p["required"] and name not in seen]
        return sorted(out, key=lambda f: -f["strength"])

    @staticmethod
    def _f(kind: str, param: str, detail: str, strength: float | None = None) -> dict:
        return {"kind": kind, "param": param, "detail": detail, "strength": STRENGTH[kind] if strength is None else strength}

    def _check_value(self, name: str, v, p: dict) -> list[dict]:
        t = vtype(v)
        if t == "empty":
            return []
        out = []
        if not fits(t, p["types"]):
            out.append(self._f("type_mismatch", name, f"'{name}' is {t}, expected {'/'.join(p['types'])}"))
        if p["opaque"] or isinstance(v, (dict, list)):
            return out
        s = str(v)
        if p["enum"] is not None and s not in p["enum"]:
            out.append(self._f("enum_violation", name, f"'{name}' is not one of its {len(p['enum'])} known values"))
        if p["max_len"] and len(s) > max(p["max_len"] * 1.5, p["max_len"] + 10):
            out.append(self._f("length_outlier", name, f"'{name}' is {len(s)} long, usually up to {p['max_len']}"))
        if p["symbols"]:
            new = sorted(symbols(s) - set(p["symbols"]))
            if new:
                out.append(self._f("charset_shift", name, f"'{name}' contains unusual characters: {' '.join(map(repr, new))}"))
        return out

    @staticmethod
    def strength(findings: list[dict]) -> float:
        """Noisy-OR of the findings: 1 - prod(1 - s)."""
        rest = 1.0
        for f in findings:
            rest *= 1 - f["strength"]
        return 1 - rest

    # --- OpenAPI 3 ----------------------------------------------------------------------------------------
    @classmethod
    def from_openapi(cls, spec: dict) -> "SchemaModel":
        """Positive model straight from an OpenAPI 3 document: no traffic needed."""
        ref = lambda o: _deref(spec, o)
        m = cls()
        for path, item in spec.get("paths", {}).items():
            tpl = template(path)
            for method, op in item.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                params = {}
                for prm in (ref(x) for x in item.get("parameters", []) + op.get("parameters", [])):
                    if prm.get("in") == "query":
                        params[prm["name"]] = _spec_param(ref(prm.get("schema", {})), prm.get("required", False), ref)
                body_open = False
                schema = ref(((op.get("requestBody") or {}).get("content", {}).get("application/json") or {}).get("schema", {}))
                if "requestBody" in op:
                    props = schema.get("properties") or {}
                    body_open = not props
                    for k, sub in props.items():
                        sub = ref(sub)
                        params[k] = _spec_param(sub, k in schema.get("required", []), ref)
                        for k2, sub2 in (sub.get("properties") or {}).items():
                            params[f"{k}.{k2}"] = _spec_param(ref(sub2), k2 in sub.get("required", []), ref)
                m.endpoints.setdefault(tpl, {"methods": {}})["methods"][method.upper()] = {"n": 0, "open": body_open, "params": params}
        return m

    # --- (de)serialisation ------------------------------------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps({"version": 1, "min_support": self.min_support, "min_share": self.min_share,
                           "endpoints": self.endpoints}, indent=1, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "SchemaModel":
        d = json.loads(text)
        m = cls(d["min_support"], d["min_share"])
        m.endpoints = d["endpoints"]
        return m

    def summary(self) -> list[dict]:
        """Learned endpoints for display: template, methods, parameter names (required marked)."""
        return [{"endpoint": tpl, "methods": {mth: {"requests": s["n"], "open": s["open"],
                                                    "params": [{"name": k, "required": p["required"], "types": p["types"],
                                                                "enum": len(p["enum"]) if p["enum"] else 0}
                                                               for k, p in sorted(s["params"].items())]}
                                              for mth, s in sorted(ep["methods"].items())}}
                for tpl, ep in sorted(self.endpoints.items())]


def _deref(spec: dict, obj: dict) -> dict:
    while isinstance(obj, dict) and "$ref" in obj:
        node = spec
        for part in obj["$ref"].lstrip("#/").split("/"):
            node = node.get(part, {})
        obj = node
    return obj


def _spec_param(schema: dict, required: bool, ref) -> dict:
    types, enum = [], schema.get("enum")
    for s in [ref(x) for x in schema.get("anyOf", []) + schema.get("oneOf", [])] or [schema]:
        t = s.get("type")
        types += {"integer": ["int"], "number": ["int", "float"], "string": ["text"], "boolean": ["bool"],
                  "array": ["list"], "object": ["object"], "null": ["null"]}.get(t, [])
        enum = enum or s.get("enum")
    return {"n": 0, "required": bool(required), "types": sorted(set(types)) or ["text"], "max_len": schema.get("maxLength", 0),
            "symbols": "", "enum": [str(e) for e in enum] if enum else None, "opaque": False}
