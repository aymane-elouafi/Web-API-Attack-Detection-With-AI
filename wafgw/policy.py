"""Policy logic shared by the engine, the console and the simulator, so "exempt" and "fuse" mean one thing."""
import json
from urllib.parse import parse_qsl

import numpy as np

DETECTORS = ("rules", "payload ML", "behavior", "schema", "coraza", "bot", "intel")      # the ones an exemption can silence


def param_names(query: str, body: str) -> set[str]:
    """Names of the query parameters and of the top-level JSON body keys."""
    names = {k for k, _ in parse_qsl(query, keep_blank_values=True)}
    try:
        obj = json.loads(body) if body else {}
        names |= set(obj) if isinstance(obj, dict) else set()
    except json.JSONDecodeError:
        pass
    return names


def exempt_detectors(exemptions: list[dict], path: str, query: str, body: str) -> set[str]:
    """Detectors silenced for this request: path starts with the prefix and the parameter (if given) is present."""
    if not exemptions:
        return set()
    names = param_names(query, body)
    return {e["detector"] for e in exemptions
            if path.startswith(e["prefix"]) and (not e.get("param") or e["param"] in names)}


def fuse(strengths: dict, skip: set = frozenset()) -> float:
    """Noisy-OR of the detector strengths (same as detection.fusion), ignoring the skipped detectors."""
    return float(1 - np.prod([1 - s for d, s in strengths.items() if d not in skip]))


def replay(events: list[dict], threshold: float, exemptions: list[dict], current_threshold: float | None = None) -> dict:
    """What would have happened to stored events under a candidate policy?

    Each event needs: id, path, query, body_snippet, detectors, risk, action. "Before" is what actually
    happened (action != allowed); "after" re-fuses the stored strengths with the candidate exemptions/threshold.
    """
    newly_allowed, newly_flagged, flagged_after = [], [], 0
    for e in events:
        before = e["action"] != "allowed"
        skip = exempt_detectors(exemptions, e["path"], e.get("query", ""), e.get("body_snippet", ""))
        after = fuse(e["detectors"], skip) >= threshold if e["detectors"] else before
        flagged_after += after
        if before and not after:
            newly_allowed.append(e["id"])
        elif after and not before:
            newly_flagged.append(e["id"])
    return {"events": len(events), "flagged_before": sum(e["action"] != "allowed" for e in events),
            "flagged_after": flagged_after, "newly_allowed": newly_allowed, "newly_flagged": newly_flagged}
