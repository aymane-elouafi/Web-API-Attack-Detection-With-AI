"""python -m wafgw [--config waf.toml]  -> proxy + admin API in one process."""
import argparse
import asyncio
import os
import sys

import uvicorn

from wafgw import config, report
from wafgw.admin import build_admin
from wafgw.engine import Engine
from wafgw.proxy import build_app
from wafgw.store import Store


def _addr(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    return host or "0.0.0.0", int(port)


def proxy_config(cfg: dict, app) -> uvicorn.Config:
    """uvicorn settings for the proxy port, with optional TLS termination ([tls] cert + key)."""
    host, port = _addr(cfg["proxy"]["listen"])
    tls = cfg["tls"]
    if bool(tls["cert"]) != bool(tls["key"]):
        raise SystemExit("[tls] needs both cert and key (or neither)")
    for f in (tls["cert"], tls["key"]):
        if f and not os.path.isfile(f):
            raise SystemExit(f"[tls] file not found: {f}")
    return uvicorn.Config(app, host=host, port=port, log_level="warning", proxy_headers=False, server_header=False,
                          ssl_certfile=tls["cert"] or None, ssl_keyfile=tls["key"] or None, timeout_keep_alive=5)


async def watch_models(engine: Engine) -> None:
    """Pick up retrained models and schema.json even while no traffic arrives (inspect() only checks when a request comes in)."""
    while True:
        await asyncio.sleep(engine.reload_every)
        engine.reload_models()


async def run(cfg: dict) -> None:
    store = Store(cfg["store"]["path"])
    engine = Engine(cfg, store)
    if engine.payload is None or engine.behavior is None:
        print("warning: AI models missing in %s (run: python -m wafgw.train); rules only" % cfg["models"]["dir"], file=sys.stderr)
    servers = []
    servers.append(uvicorn.Server(proxy_config(cfg, build_app(cfg, engine, store))))
    try:
        host, port = _addr(cfg["admin"]["listen"])
        servers.append(uvicorn.Server(uvicorn.Config(build_admin(engine, store, os.environ.get("WAF_ADMIN_TOKEN"), cfg),
                                                     host=host, port=port, log_level="warning")))
    except RuntimeError as exc:
        print(f"warning: {exc}", file=sys.stderr)
    print(f"gateway {'https' if cfg['tls']['cert'] else 'http'}://{cfg['proxy']['listen']} -> {cfg['proxy']['upstream']}  mode={engine.mode}  "
          f"admin={'on ' + cfg['admin']['listen'] if len(servers) > 1 else 'OFF'}")
    await asyncio.gather(watch_models(engine), report.schedule(cfg, store, engine), *(s.serve() for s in servers))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    asyncio.run(run(config.load(ap.parse_args().config)))


if __name__ == "__main__":
    main()
