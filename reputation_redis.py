import os
import redis
from datetime import datetime, timezone

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")

def _r():
    return redis.from_url(REDIS_URL, decode_responses=True)

def rep_key(agent_id: str) -> str:
    return f"rep:{agent_id}"

def get_rep(agent_id: str) -> float:
    r = _r()
    val = r.get(rep_key(agent_id))
    if val is None:
        # default starting rep
        return 1.0
    try:
        return float(val)
    except Exception:
        return 1.0

def set_rep(agent_id: str, score: float) -> float:
    r = _r()
    score = max(0.0, min(1.0, float(score)))
    r.set(rep_key(agent_id), str(score))
    r.hset(f"repmeta:{agent_id}", mapping={
        "score": str(score),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    return score

def bump_rep(agent_id: str, delta: float) -> float:
    current = get_rep(agent_id)
    return set_rep(agent_id, current + float(delta))

def apply_outcome(agent_id: str, decision: str) -> float:
    """
    v1 scoring:
      allow  -> +0.01 (cap 1.0)
      review -> -0.03
      deny   -> -0.08
    """
    d = (decision or "").lower()
    if d == "allow":
        return bump_rep(agent_id, +0.01)
    if d == "review":
        return bump_rep(agent_id, -0.03)
    if d == "deny":
        return bump_rep(agent_id, -0.08)
    return get_rep(agent_id)
