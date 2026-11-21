"""IP reputation and geo-style rules, from local files the operator provides (nothing is downloaded here).

Files in the intel directory (default data/intel/, see wafgw/samples/ for the formats):
  *.block.txt   blocklist, one IP or CIDR per line; '#' / ';' comments; "1.2.3.0/24 ; SBL123" (Spamhaus DROP) and
                FireHOL .netset files work as they are
  *.allow.txt   allowlist, same format: these clients skip inspection
  networks.csv  cidr,country,asn[,org]   (a header line is optional)
Rules on top of networks.csv are set in waf.toml or at runtime: country_deny = ["KP"], asn_deny = [64500].
Optional DNSBL lookups (off by default) run in background threads, so a request never waits for DNS.

Strength convention: 0.5 = alert on its own. A blocklist hit is 0.8, a country/ASN rule 0.6, a DNSBL hit 0.7.
Files are re-read when their modification time changes.
"""
import csv
import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MAX_BYTES = 10 * 1024 * 1024
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,60}$")
SUFFIX = {"blocklist": ".block.txt", "allowlist": ".allow.txt"}
NETWORKS = "networks.csv"


class PrefixTable:
    """CIDR -> metadata with longest-prefix match in at most 33 dict lookups, however big the list is."""

    def __init__(self):
        self.t: dict[int, dict[int, dict[int, object]]] = {4: {}, 6: {}}
        self.count = 0

    def add(self, net, meta) -> None:
        self.t[net.version].setdefault(net.prefixlen, {})[int(net.network_address)] = meta
        self.count += 1

    def lookup(self, addr):
        bits = 32 if addr.version == 4 else 128
        value = int(addr)
        for plen in sorted(self.t[addr.version], reverse=True):
            meta = self.t[addr.version][plen].get(value >> (bits - plen) << (bits - plen))
            if meta is not None:
                return meta
        return None


def parse_list(text: str) -> tuple[list[tuple], int]:
    """([(network, note)], bad_line_count). Accepts plain lists, Spamhaus DROP and FireHOL netsets."""
    out, bad = [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;/":
            continue
        token = re.split(r"[\s;#]+", line, maxsplit=1)[0]
        note = line[len(token):].lstrip(" ;#\t")
        try:
            out.append((ipaddress.ip_network(token, strict=False), note[:80]))
        except ValueError:
            bad += 1
    return out, bad


def parse_networks(text: str) -> tuple[list[tuple], int]:
    """([(network, {country, asn, org})], bad_line_count) from cidr,country,asn[,org] lines."""
    out, bad = [], 0
    for row in csv.reader(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")):
        if row and row[0].strip().lower() in ("cidr", "network", "prefix"):
            continue                                          # header line
        try:
            net = ipaddress.ip_network(row[0].strip(), strict=False)
            asn = row[2].strip().upper().removeprefix("AS") if len(row) > 2 else ""
            out.append((net, {"country": row[1].strip().upper() if len(row) > 1 else "", "asn": int(asn) if asn else 0,
                              "org": row[3].strip() if len(row) > 3 else ""}))
        except (ValueError, IndexError):
            bad += 1
    return out, bad


class Intel:
    def __init__(self, directory: str, country_deny=(), asn_deny=(), dnsbl_zones=(), dnsbl_enabled=False, resolver=None,
                 dnsbl_ttl: float = 3600.0):
        self.dir = Path(directory)
        self.country_deny, self.asn_deny = {c.upper() for c in country_deny}, {int(a) for a in asn_deny}
        self.dnsbl_zones, self.dnsbl_enabled, self.dnsbl_ttl = list(dnsbl_zones), dnsbl_enabled, dnsbl_ttl
        self.resolver = resolver or _resolve
        self.block, self.allow, self.geo = PrefixTable(), PrefixTable(), PrefixTable()
        self.files: list[dict] = []
        self._stamps: dict | None = None
        self._dnsbl_cache: dict[str, tuple[float, str]] = {}
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dnsbl") if dnsbl_enabled else None
        self._pending: dict[str, object] = {}
        self.reload()

    # --- loading ---------------------------------------------------------------------------------
    def _stamp(self) -> dict:
        return {p.name: (p.stat().st_mtime_ns, p.stat().st_size) for p in sorted(self.dir.glob("*")) if p.is_file()} if self.dir.is_dir() else {}

    def reload_if_changed(self) -> bool:
        if self._stamp() == self._stamps:
            return False
        self.reload()
        return True

    def reload(self) -> None:
        self._stamps = self._stamp()
        block, allow, geo, files = PrefixTable(), PrefixTable(), PrefixTable(), []
        for name in self._stamps:
            path = self.dir / name
            if name.endswith(SUFFIX["blocklist"]) or name.endswith(SUFFIX["allowlist"]) or name == NETWORKS:
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                if name == NETWORKS:
                    rows, bad = parse_networks(text)
                    [geo.add(n, m) for n, m in rows]
                    kind = "networks"
                else:
                    rows, bad = parse_list(text)
                    table, kind = (block, "blocklist") if name.endswith(SUFFIX["blocklist"]) else (allow, "allowlist")
                    [table.add(n, {"file": name, "note": note}) for n, note in rows]
                files.append({"name": name, "kind": kind, "entries": len(rows), "bad_lines": bad,
                              "modified": path.stat().st_mtime})
        self.block, self.allow, self.geo, self.files = block, allow, geo, files   # swap in one go: readers never see half a list

    # --- lookups ---------------------------------------------------------------------------------
    def allowed(self, ip: str) -> dict | None:
        addr = _addr(ip)
        return self.allow.lookup(addr) if addr else None

    def check(self, ip: str) -> tuple[float, str]:
        """(strength, plain-language reason); (0, '') when nothing is known against the client."""
        addr = _addr(ip)
        if addr is None:
            return 0.0, ""
        parts = []
        if (hit := self.block.lookup(addr)):
            parts.append((0.8, f"listed in blocklist {hit['file']}" + (f" ({hit['note']})" if hit["note"] else "")))
        if (g := self.geo.lookup(addr)):
            if g["country"] in self.country_deny:
                parts.append((0.6, f"country {g['country']} is denied by policy"))
            if g["asn"] and g["asn"] in self.asn_deny:
                parts.append((0.6, f"network AS{g['asn']}{' (' + g['org'] + ')' if g['org'] else ''} is denied by policy"))
        if self.dnsbl_enabled and addr.version == 4 and (zone := self._dnsbl(ip)):
            parts.append((0.7, f"listed on DNSBL {zone}"))
        if not parts:
            return 0.0, ""
        keep = 1.0
        for s, _ in parts:
            keep *= 1 - s
        return min(1 - keep, 0.95), "; ".join(d for _, d in parts)

    def lookup(self, ip: str) -> dict:
        """Everything known about one IP, for the console's 'why is this listed' box."""
        addr = _addr(ip)
        if addr is None:
            raise ValueError("not an IP address")
        strength, reason = self.check(ip)
        return {"ip": ip, "allowlist": self.allow.lookup(addr), "blocklist": self.block.lookup(addr), "network": self.geo.lookup(addr),
                "strength": strength, "reason": reason}

    # --- DNSBL (opt-in, never blocks a request) --------------------------------------------------
    def _dnsbl(self, ip: str) -> str:
        now = time.time()
        cached = self._dnsbl_cache.get(ip)
        if cached and now - cached[0] < self.dnsbl_ttl:
            return cached[1]
        if ip not in self._pending and self._pool and self.dnsbl_zones:
            self._pending[ip] = self._pool.submit(self._lookup_zones, ip)
        fut = self._pending.get(ip)
        if fut is not None and fut.done():
            self._dnsbl_cache[ip] = (now, fut.result())
            del self._pending[ip]
            return self._dnsbl_cache[ip][1]
        return ""                                            # answer not in yet: unknown counts as clean

    def _lookup_zones(self, ip: str) -> str:
        rev = ".".join(reversed(ip.split(".")))
        return next((z for z in self.dnsbl_zones if self.resolver(f"{rev}.{z}")), "")

    # --- management (admin API) ------------------------------------------------------------------
    def save(self, kind: str, name: str, text: str) -> dict:
        if len(text.encode()) > MAX_BYTES:
            raise ValueError("file too large (10 MB limit)")
        if kind == "networks":
            fname, (rows, bad) = NETWORKS, parse_networks(text)
        elif kind in SUFFIX:
            if not NAME.match(name):
                raise ValueError("name may contain letters, digits, _ . - (max 61 characters)")
            fname, (rows, bad) = name.removesuffix(SUFFIX[kind]) + SUFFIX[kind], parse_list(text)
        else:
            raise ValueError("kind must be blocklist, allowlist or networks")
        if not rows:
            raise ValueError("no valid entries found")
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / (fname + ".tmp")
        tmp.write_text(text)
        tmp.replace(self.dir / fname)                        # atomic: a reload never sees half a file
        self.reload()
        return {"file": fname, "entries": len(rows), "bad_lines": bad}

    def delete(self, kind: str, name: str) -> bool:
        fname = NETWORKS if kind == "networks" else name.removesuffix(SUFFIX.get(kind, "")) + SUFFIX.get(kind, "")
        path = self.dir / fname
        if not NAME.match(fname) or not path.is_file():
            return False
        path.unlink()
        self.reload()
        return True

    def export(self, kind: str, name: str) -> str:
        fname = NETWORKS if kind == "networks" else name.removesuffix(SUFFIX.get(kind, "")) + SUFFIX.get(kind, "")
        if not NAME.match(fname) or not (self.dir / fname).is_file():
            raise KeyError("no such file")
        return (self.dir / fname).read_text()

    def set_policy(self, country_deny=None, asn_deny=None) -> None:
        if country_deny is not None:
            self.country_deny = {str(c).upper() for c in country_deny}
        if asn_deny is not None:
            self.asn_deny = {int(str(a).upper().removeprefix("AS")) for a in asn_deny}

    def status(self) -> dict:
        return {"dir": str(self.dir), "files": self.files, "country_deny": sorted(self.country_deny), "asn_deny": sorted(self.asn_deny),
                "dnsbl": {"enabled": self.dnsbl_enabled, "zones": self.dnsbl_zones},
                "entries": {"blocklist": self.block.count, "allowlist": self.allow.count, "networks": self.geo.count}}


def _addr(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def _resolve(host: str) -> bool:
    import socket
    try:
        socket.setdefaulttimeout(2.0)
        socket.gethostbyname(host)
        return True
    except OSError:
        return False
