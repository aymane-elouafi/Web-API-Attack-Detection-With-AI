"""Bot / scanner detector: is this client a machine, and a hostile one?

Never decided by the User-Agent alone (it is free to fake). Three kinds of evidence, each with a
plain-language reason, combined with the same noisy-OR as the other detectors:

  * tool signatures   a scanner name in the User-Agent (strong); a default scripting client such as
                      curl or python-requests (weak, plenty of legitimate scripts exist)
  * header anomalies  a "browser" that lacks headers every browser sends, HTTP/1.0, no User-Agent
                      (weak; checked only when the proxy passes the request headers)
  * rhythm            per client over the last 60 s: machine-regular timing, request bursts,
                      walking many different URLs that mostly do not exist, sweeps of failing
                      requests, many requests without any session credential

Strength convention (same as every detector): 0.5 = would alert on its own. Weak evidence stays
well below that, so it only tips the balance together with another detector. These numbers are a
stated policy, not tuned on any test set.
"""
import re
from collections import defaultdict, deque

TOOLS = re.compile(r"sqlmap|nikto|nuclei|wfuzz|gobuster|dirbuster|dirb\b|ffuf|feroxbuster|hydra|medusa|masscan|"
                   r"nmap|zgrab|nessus|acunetix|wpscan|havij|metasploit|openvas|arachni|skipfish|w3af|whatweb", re.I)
AUTOMATION = re.compile(r"^(curl|wget|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|libwww-perl|"
                        r"java/|apache-httpclient|scrapy|postmanruntime|insomnia|httpie)", re.I)
BROWSERISH = re.compile(r"mozilla/5\.0.*(chrome|safari|firefox|gecko|applewebkit)", re.I)

WINDOW = 60.0
MIN_REQUESTS = 10          # rhythm needs a few requests before it says anything


def _combine(parts: list[tuple[str, float, str]]) -> tuple[float, str]:
    """Noisy-OR of (kind, strength, detail) findings -> (strength, 'kind: detail; ...')."""
    keep = 1.0
    for _, s, _ in parts:
        keep *= 1 - s
    return min(1 - keep, 0.95), "; ".join(f"{k}: {d}" for k, _, d in parts)


class BotDetector:
    def __init__(self, window: float = WINDOW, max_clients: int = 10_000):
        self.window, self.max_clients, self.calls = window, max_clients, 0
        self.hist: dict[str, deque] = defaultdict(deque)     # ip -> [ts, path, status, has_credential]

    # --- one request -----------------------------------------------------------------------------
    def inspect(self, info: dict) -> tuple[float, str, list | None]:
        """(strength, readable reasons, the history entry so observe() can add the status later)."""
        ts, ip = info["ts"], info["client_ip"]
        headers = info.get("headers")                         # None = proxy did not pass them (offline evaluation)
        has_cred = bool(info.get("session")) or (headers is not None and any(k in (b"cookie", b"authorization") for k, _ in headers))
        h = self.hist[ip]
        entry = [ts, info["path"], 0, has_cred]               # status 0 = answer not known yet
        h.append(entry)
        while h[0][0] < ts - self.window:
            h.popleft()
        self.calls += 1
        if self.calls % 1000 == 0:
            self._evict(ts)
        parts = self._signatures(info, headers) + self._rhythm(h, headers is not None)
        if not parts:
            return 0.0, "", entry
        strength, detail = _combine(parts)
        return strength, detail, entry

    def _signatures(self, info: dict, headers) -> list:
        ua, parts = info.get("user_agent", ""), []
        if (m := TOOLS.search(ua)):
            parts.append(("attack tool", 0.6, f"User-Agent names the scanner “{m.group(0).lower()}”"))
        elif not ua.strip():
            parts.append(("no user agent", 0.15, "the client does not say what it is"))
        elif AUTOMATION.search(ua):
            parts.append(("automation client", 0.15, f"scripting client “{ua.split('/')[0][:24]}” (legitimate scripts look the same)"))
        if headers is not None:
            names = {k for k, _ in headers}
            if BROWSERISH.search(ua):
                missing = [n.decode() for n in (b"accept", b"accept-language") if n not in names]
                if missing:
                    parts.append(("fake browser", min(0.1 * len(missing), 0.2),
                                  f"claims to be a browser but sends no {' or '.join(missing)} header"))
            if info.get("http_version") == "1.0":
                parts.append(("old protocol", 0.1, "HTTP/1.0, which browsers no longer use"))
        return parts

    def _rhythm(self, h: deque, headers_known: bool) -> list:
        n = len(h)
        if n < MIN_REQUESTS:
            return []
        parts, times = [], [e[0] for e in h]
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps)
        if mean > 0:
            cv = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5 / mean
            if mean <= 5 and cv < 0.2:
                parts.append(("machine timing", 0.35, f"{n} requests at a steady {mean:.1f} s rhythm (variation {cv:.0%}, people are irregular)"))
        span = times[-1] - times[0]
        if span > 0 and (rate := (n - 1) / span) >= 5:
            parts.append(("burst", 0.5 if rate >= 15 else 0.3, f"{rate:.0f} requests per second for {span:.0f} s"))
        known = [e for e in h if e[2]]
        paths, missing = {e[1] for e in h}, sum(e[2] == 404 for e in known)
        if len(paths) >= 8 and known and missing / len(known) >= 0.5:
            parts.append(("URL walking", 0.5, f"asked for {len(paths)} different URLs, {missing / len(known):.0%} of them do not exist"))
        failed, denied = sum(e[2] >= 400 for e in known), sum(e[2] in (401, 403) for e in known)
        if len(known) >= MIN_REQUESTS and denied / len(known) >= 0.8:
            parts.append(("credential guessing", 0.5, f"{denied} of the last {len(known)} requests were refused as unauthorised"))
        elif len(known) >= MIN_REQUESTS and failed / len(known) >= 0.8:
            parts.append(("failing sweep", 0.4, f"{failed} of the last {len(known)} requests failed"))
        if headers_known and n >= 20 and not any(e[3] for e in h):
            parts.append(("no session", 0.2, f"{n} requests in {span:.0f} s without any cookie or token"))
        return parts

    # --- housekeeping ----------------------------------------------------------------------------
    def _evict(self, now: float) -> None:
        for ip in [ip for ip, h in self.hist.items() if not h or h[-1][0] < now - 10 * self.window]:
            del self.hist[ip]
        if len(self.hist) > self.max_clients:
            self.hist.clear()                                 # shortcut: drop all state, re-learn within a minute
