import hashlib
import json
from typing import Any, Dict


def canonicalize_action(action: Dict[str, Any]) -> str:
    if not isinstance(action, dict):
        raise ValueError("Action must be a dict")
    return json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def deterministic_action_hash(agent_id: str, action: Dict[str, Any]) -> str:
    if not agent_id:
        raise ValueError("agent_id is required")
    canonical = canonicalize_action(action)
    material = f"{agent_id}|{canonical}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
