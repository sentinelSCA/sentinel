import json
import os
import time
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

PENDING_Q = "ops:actions:needs_human"
APPROVED_Q = "ops:actions:approved"
REJECTED_Q = "ops:actions:rejected"
EXECUTED_Q = "ops:actions:executed"

def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)

def record_key(action_id: str) -> str:
    return f"ops:actions:record:{action_id}"

def _execution_payload(now: int, mode: str = "auto") -> dict:
    return {
        "ok": True,
        "executed_ts": now,
        "mode": mode,
    }

def create_action(
    action_id: str,
    agent_id: str,
    action: dict,
    decision: str,
    risk: str,
    risk_score: float,
    reason: str,
    ttl: int = 86400,
) -> dict:
    r = get_redis()
    now = int(time.time())

    status = "pending" if decision == "review" else decision

    rec = {
        "action_id": action_id,
        "agent_id": agent_id,
        "action": action,
        "decision": decision,
        "status": status,
        "risk": risk,
        "risk_score": float(risk_score),
        "reason": reason,
        "created_ts": now,
    }

    if decision == "review":
        r.setex(record_key(action_id), ttl, json.dumps(rec, separators=(",", ":")))
        r.rpush(PENDING_Q, action_id)

    elif decision == "deny":
        rec["status"] = "rejected"
        rec["decision"] = "rejected"
        rec["error"] = "rejected"
        rec["rejected_ts"] = now
        r.setex(record_key(action_id), ttl, json.dumps(rec, separators=(",", ":")))
        r.rpush(REJECTED_Q, json.dumps(rec, separators=(",", ":")))

    elif decision == "allow":
        rec["status"] = "approved"
        rec["decision"] = "approved"
        rec["approved_ts"] = now
        r.rpush(APPROVED_Q, json.dumps(rec, separators=(",", ":")))

        rec["execution"] = _execution_payload(now, mode="auto")
        rec["status"] = "executed"
        rec["executed_ts"] = now
        r.setex(record_key(action_id), ttl, json.dumps(rec, separators=(",", ":")))
        r.rpush(EXECUTED_Q, json.dumps(rec, separators=(",", ":")))

    return rec

def load_action(action_id: str) -> dict | None:
    r = get_redis()
    raw = r.get(record_key(action_id))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

def save_action(action_id: str, rec: dict, ttl: int = 86400) -> None:
    r = get_redis()
    r.setex(record_key(action_id), ttl, json.dumps(rec, separators=(",", ":")))

def approve_action(action_id: str) -> dict | None:
    r = get_redis()
    rec = load_action(action_id)
    if not rec:
        return None

    now = int(time.time())

    rec["status"] = "approved"
    rec["decision"] = "approved"
    rec["approved_ts"] = now
    r.lrem(PENDING_Q, 0, action_id)
    r.rpush(APPROVED_Q, json.dumps(rec, separators=(",", ":")))

    rec["execution"] = _execution_payload(now, mode="manual")
    rec["status"] = "executed"
    rec["executed_ts"] = now

    save_action(action_id, rec)
    r.rpush(EXECUTED_Q, json.dumps(rec, separators=(",", ":")))

    return rec

def reject_action(action_id: str, reason: str = "manual rejection") -> dict | None:
    r = get_redis()
    rec = load_action(action_id)
    if not rec:
        return None

    rec["status"] = "rejected"
    rec["decision"] = "rejected"
    rec["error"] = "rejected"
    rec["reason"] = reason
    rec["rejected_ts"] = int(time.time())
    save_action(action_id, rec)

    r.lrem(PENDING_Q, 0, action_id)
    r.rpush(REJECTED_Q, json.dumps(rec, separators=(",", ":")))
    return rec

def safe_len(key: str) -> int:
    try:
        return int(get_redis().llen(key))
    except Exception:
        return -1

def safe_lrange(key: str, start: int, end: int) -> list[str]:
    try:
        return get_redis().lrange(key, start, end)
    except Exception:
        return []

def dashboard_counts() -> dict:
    return {
        "needs_human": safe_len(PENDING_Q),
        "approved": safe_len(APPROVED_Q),
        "rejected": safe_len(REJECTED_Q),
        "executed": safe_len(EXECUTED_Q),
    }

def dashboard_lists() -> dict:
    return {
        "needs_human": safe_lrange(PENDING_Q, -5, -1),
        "approved": safe_lrange(APPROVED_Q, -5, -1),
        "rejected": safe_lrange(REJECTED_Q, -5, -1),
        "executed": safe_lrange(EXECUTED_Q, -5, -1),
    }
