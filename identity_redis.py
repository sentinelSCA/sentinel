import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import redis

def _r() -> redis.Redis:
    url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    return redis.from_url(url, decode_responses=True)

def compute_agent_id(pub_bytes: bytes) -> str:
    h = hashlib.sha256(pub_bytes).hexdigest()[:16]
    return f"agent_{h}"

def register_agent(pub_b64: str, display_name: str = "", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    metadata = metadata or {}

    try:
        pub_bytes = base64.b64decode(pub_b64.encode("utf-8"), validate=True)
    except Exception:
        raise ValueError("bad pub_b64 (must be base64)")

    agent_id = compute_agent_id(pub_bytes)
    key = f"agent:{agent_id}"

    payload = {
        "agent_id": agent_id,
        "pub_b64": pub_b64,
        "display_name": display_name or "",
        "metadata": metadata,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    r = _r()
    r.set(key, json.dumps(payload, separators=(",", ":"), sort_keys=True))
    r.sadd("agents:set", agent_id)

    return payload

def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    r = _r()
    raw = r.get(f"agent:{agent_id}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None
