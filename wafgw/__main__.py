"""python -m wafgw [--config waf.toml]  -> proxy + admin API in one process."""
import argparse
import asyncio
import os
import sys

import uvicorn

from wafgw import config
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.proxy import build_app
from wafgw.store import Store


def _addr(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    return host or "0.0.0.0", int(port)


async def run(cfg: dict) -> None:
    store = Store(cfg["store"]["path"])
    engine = Engine(cfg, store)
    if engine.payload is None or engine.behavior is None:
        print("warning: AI models missing in %s (run: python -m wafgw.train); rules only" % cfg["models"]["dir"], file=sys.stderr)
    servers = []
    host, port = _addr(cfg["proxy"]["listen"])
    servers.append(uvicorn.Server(uvicorn.Config(build_app(cfg, engine, store), host=host, port=port,
                                                 log_level="warning", proxy_headers=False, server_header=False)))
    try:
        host, port = _addr(cfg["admin"]["listen"])
        servers.append(uvicorn.Server(uvicorn.Config(build_admin(engine, store, os.environ.get("WAF_ADMIN_TOKEN")),
                                                     host=host, port=port, log_level="warning")))
    except RuntimeError as exc:
        print(f"warning: {exc}", file=sys.stderr)
    print(f"gateway {cfg['proxy']['listen']} -> {cfg['proxy']['upstream']}  mode={engine.mode}  "
          f"admin={'on ' + cfg['admin']['listen'] if len(servers) > 1 else 'OFF'}")
    await asyncio.gather(*(s.serve() for s in servers))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    asyncio.run(run(config.load(ap.parse_args().config)))


if __name__ == "__main__":
    main()
