"""Optional LLM narrative for an incident. OFF by default and never required: the rule-based write-up in
wafgw/incidents.py is always there. Nothing leaves this machine unless the operator sets [explainer] enabled = true.

What is sent: the incident's computed facts only (attack classes, counts, outcome, the order of events, path shapes).
Never sent: request bodies, headers, cookies, query strings or full IPs (the last octet is masked unless send_ip = true).
Works with any OpenAI-compatible or Anthropic-compatible endpoint (for example a local gateway such as OmniRoute).
"""
import os
import re

import httpx

DEFAULTS = {"enabled": False, "url": "", "format": "openai", "model": "", "api_key_env": "", "timeout_s": 20, "send_ip": False}
SYSTEM = ("You are a security analyst assistant. Using ONLY the JSON facts you are given, write at most 120 words: "
          "what the client did, how serious it is and what to do first. Do not invent details. Plain language, no markdown.")


def mask_ip(ip: str) -> str:
    return re.sub(r"(\d+\.\d+\.\d+\.)\d+", r"\1x", ip) if "." in ip else ip.rsplit(":", 1)[0] + ":x"


def facts(incident: dict, send_ip: bool = False) -> dict:
    """The only thing the LLM sees. Built from computed fields; free-text evidence from requests is left out on purpose."""
    return {"client": incident["client_ip"] if send_ip else mask_ip(incident["client_ip"]),
            "severity": incident["severity"], "confidence": incident["confidence"], "flagged_requests": incident["events"],
            "duration_seconds": incident["duration_s"], "techniques": [c["name"] for c in incident["classes"]],
            "references": incident["refs"], "detectors_that_fired": incident["detectors"], "outcome": incident["outcome"]["detail"],
            "statuses": incident["statuses"], "endpoints": [p for p, _ in incident["paths"]],
            "timeline": [f"{s['count']}x {s['method']} {s['path']} ({', '.join(s['classes'])})" for s in incident["timeline"] if "more" not in s][:12]}


def status(cfg: dict | None) -> dict:
    cfg = {**DEFAULTS, **(cfg or {})}
    return {"enabled": bool(cfg["enabled"] and cfg["url"] and cfg["model"]), "model": cfg["model"], "format": cfg["format"],
            "sends_ip": bool(cfg["send_ip"]), "endpoint_host": httpx.URL(cfg["url"]).host if cfg["url"] else ""}


def _endpoint(cfg: dict) -> str:
    url = cfg["url"].rstrip("/")
    tail = "/v1/messages" if cfg["format"] == "anthropic" else "/v1/chat/completions"
    return url if url.endswith(("/messages", "/completions")) else url + tail


async def narrate(incident: dict, cfg: dict | None, client: httpx.AsyncClient | None = None) -> dict:
    """Ask the configured endpoint for a short narrative. Raises PermissionError when the operator has not enabled it."""
    cfg = {**DEFAULTS, **(cfg or {})}
    if not (cfg["enabled"] and cfg["url"] and cfg["model"]):
        raise PermissionError("the LLM explainer is disabled; set [explainer] enabled, url and model in waf.toml")
    user = "Incident facts (JSON):\n" + str(facts(incident, cfg["send_ip"]))
    key = os.environ.get(cfg["api_key_env"], "") if cfg["api_key_env"] else ""
    if cfg["format"] == "anthropic":
        headers, body = {"anthropic-version": "2023-06-01"}, {"model": cfg["model"], "max_tokens": 300, "system": SYSTEM,
                                                              "messages": [{"role": "user", "content": user}]}
        key and headers.update({"x-api-key": key, "authorization": f"Bearer {key}"})
    else:
        headers, body = {}, {"model": cfg["model"], "max_tokens": 300, "messages": [{"role": "system", "content": SYSTEM},
                                                                                   {"role": "user", "content": user}]}
        key and headers.update({"authorization": f"Bearer {key}"})     # a local gateway may need no key; an empty "Bearer " is an illegal header
    own = client is None
    client = client or httpx.AsyncClient(timeout=cfg["timeout_s"])
    try:
        r = await client.post(_endpoint(cfg), json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        text = data["content"][0]["text"] if cfg["format"] == "anthropic" else data["choices"][0]["message"]["content"]
    finally:
        own and await client.aclose()
    return {"text": text.strip(), "source": "llm", "model": cfg["model"], "note": "Written by a language model from the facts above; check it against the rule-based write-up."}
