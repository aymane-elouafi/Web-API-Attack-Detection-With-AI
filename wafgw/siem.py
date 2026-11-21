"""Ship events to a SIEM: a JSON-lines file (Filebeat / Splunk forwarder tail it) and/or CEF over UDP syslog."""
import json
import socket

_HEAD = str.maketrans({"\\": "\\\\", "|": "\\|", "\n": " ", "\r": " "})
_EXT = str.maketrans({"\\": "\\\\", "=": "\\=", "\n": "\\n", "\r": "\\n"})


def cef(e: dict) -> str:
    """ArcSight Common Event Format: understood by Splunk, QRadar, ArcSight, Sentinel, Elastic."""
    reasons = json.loads(e.get("reasons") or "[]")
    top = max(reasons, key=lambda r: r.get("strength", 0), default={})
    sig = str(top.get("detector", "request")).translate(_HEAD)
    ext = {"src": e["client_ip"], "requestMethod": e["method"], "request": e["path"], "act": e["action"],
           "dhost": e.get("host", ""), "requestClientApplication": e.get("user_agent", ""), "rt": int(e["ts"] * 1000),
           "externalId": e["request_id"], "cn1": e["risk"], "cn1Label": "risk", "msg": top.get("detail", "")}
    name = f"{e['action']} {e['method']} {e['path']}".translate(_HEAD)
    return (f"CEF:0|wafgw|web-api-waf|1.0|{sig}|{name}|{round(e['risk'] * 10)}|" + " ".join(f"{k}={str(v).translate(_EXT)}" for k, v in ext.items()))


class Siem:
    def __init__(self, cfg: dict):
        self.only_flagged = cfg["only_flagged"]
        self.file = open(cfg["file"], "a", buffering=1) if cfg["file"] else None   # line-buffered: one write() per event, safe across workers
        self.sock, self.addr = None, None
        if cfg["syslog"]:
            host, _, port = cfg["syslog"].rpartition(":")
            self.sock, self.addr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), (host, int(port))

    def emit(self, e: dict) -> None:
        if self.only_flagged and e["action"] == "allowed":
            return
        try:
            if self.file:
                self.file.write(json.dumps(e, separators=(",", ":")) + "\n")
            if self.sock:       # shortcut: UDP can drop and a line over ~64 KB is not sent; use the file + a forwarder when loss matters
                self.sock.sendto(f"<14>wafgw: {cef(e)}".encode()[:65000], self.addr)
        except OSError:
            pass                # a SIEM outage must never hurt traffic
