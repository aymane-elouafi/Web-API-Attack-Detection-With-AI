"""python -m dashboard  -> the console on :8100 (127.0.0.1 unless CONSOLE_PASSWORD is set)."""
import os
import sys

import uvicorn

if __name__ == "__main__":
    host = os.environ.get("CONSOLE_HOST") or ("0.0.0.0" if os.environ.get("CONSOLE_PASSWORD") else "127.0.0.1")
    if not os.environ.get("WAF_ADMIN_TOKEN"):
        print("warning: WAF_ADMIN_TOKEN is not set; the gateway pages will fail", file=sys.stderr)
    if not os.environ.get("CONSOLE_PASSWORD"):
        print("note: no CONSOLE_PASSWORD, so the console has no login and is bound to 127.0.0.1 only", file=sys.stderr)
    uvicorn.run("dashboard.app:app", host=host, port=int(os.environ.get("CONSOLE_PORT", "8100")), log_level="warning")
