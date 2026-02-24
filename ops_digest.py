import json
import hashlib
from typing import Any, Dict


def _canon(obj: Dict[str, Any]) -> str:
    # Stable JSON across all workers
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_action(action: Dict[str, Any]) -> str:
    """
    Digest ONLY immutable intent:
      - type
      - target
      - params
    Never include: reason, timestamps, manager, fingerprint, incident_id, etc.
    """
    payload = {
        "type": (action.get("type") or "").strip(),
        "target": (action.get("target") or "").strip(),
        "params": action.get("params") or {},
    }
    h = hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()
    return f"sha256:{h}"
