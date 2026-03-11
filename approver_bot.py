import os
import time
import json
import redis

from ops_digest import digest_action

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

PROPOSED_Q = os.getenv("OPS_PROPOSED_Q", "ops:actions:proposed").strip()
INFLIGHT_Q = os.getenv("OPS_PROPOSED_INFLIGHT_Q", "ops:actions:proposed:inflight").strip()
APPROVED_Q = os.getenv("OPS_APPROVED_Q", "ops:actions:approved").strip()
REJECTED_Q = os.getenv("OPS_REJECTED_Q", "ops:actions:rejected").strip()
HUMAN_Q = os.getenv("OPS_HUMAN_Q", "ops:actions:needs_human").strip()

APPROVER_ID = os.getenv("APPROVER_ID", "human_approver").strip()

AUTO_APPROVE = os.getenv("AUTO_APPROVE", "0").strip() == "1"
AUTO_TYPES = [s.strip() for s in os.getenv("AUTO_TYPES", "").split(",") if s.strip()]
AUTO_TARGETS = [s.strip() for s in os.getenv("AUTO_TARGETS", "").split(",") if s.strip()]

REQUIRE_DIGEST_MATCH = os.getenv("REQUIRE_DIGEST_MATCH", "1").strip() == "1"
POLL_SEC = float(os.getenv("APPROVER_POLL_SEC", "1").strip() or "1")

r = redis.from_url(REDIS_URL, decode_responses=True)


def now_ts() -> int:
    return int(time.time())


def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def jload(s: str):
    return json.loads(s)


def record_key(action_id: str) -> str:
    return f"ops:actions:record:{action_id}"


def ttl_from_record(rec: dict, default_ttl: int = 900) -> int:
    try:
        exp = int(rec.get("expires_ts") or 0)
        if exp <= 0:
            return default_ttl
        ttl = exp - now_ts()
        return max(60, min(ttl, default_ttl))
    except Exception:
        return default_ttl


def save_record(action_id: str, rec: dict):
    ttl = ttl_from_record(rec)
    r.setex(record_key(action_id), ttl, jdump(rec))


def should_auto(action_type: str, target: str) -> bool:
    if not AUTO_APPROVE:
        return False
    if AUTO_TYPES and action_type not in AUTO_TYPES:
        return False
    if AUTO_TARGETS and target not in AUTO_TARGETS:
        return False
    return True


def reject(action_id: str, reason: str):
    raw = r.get(record_key(action_id))
    rec = jload(raw) if raw else {
        "action_id": action_id,
        "status": "proposed",
        "created_ts": now_ts(),
        "expires_ts": now_ts() + 900,
    }

    rec["status"] = "rejected"
    rec["rejection"] = {
        "rejected_by": APPROVER_ID,
        "rejected_ts": now_ts(),
        "reason": reason[:500],
    }

    save_record(action_id, rec)

    r.rpush(REJECTED_Q, jdump({
        "action_id": action_id,
        "error": "rejected",
        "reason": reason[:800],
        "ts": now_ts(),
    }))


def approve(action_id: str, rec: dict, computed_digest: str):
    rec["status"] = "approved"
    rec.setdefault("approval", {})
    rec["approval"]["approved_by"] = APPROVER_ID
    rec["approval"]["approved_ts"] = now_ts()
    rec["approval"]["approved_digest"] = computed_digest

    save_record(action_id, rec)

    r.rpush(APPROVED_Q, jdump({
        "action_id": action_id,
        "approved_msg": rec,
        "ts": now_ts(),
    }))

    print("approved:", action_id, flush=True)


def needs_human(action_id: str, rec: dict):
    rec["status"] = "needs_human_approval"
    save_record(action_id, rec)
    r.rpush(HUMAN_Q, action_id)
    print("needs human approval:", action_id, flush=True)


def run():
    print("approver-bot started (human review enabled).", flush=True)
    print("PROPOSED_Q =", PROPOSED_Q, flush=True)
    print("INFLIGHT_Q =", INFLIGHT_Q, flush=True)
    print("HUMAN_Q    =", HUMAN_Q, flush=True)

    while True:
        try:
            item = r.brpoplpush(PROPOSED_Q, INFLIGHT_Q, timeout=2)
            if not item:
                time.sleep(POLL_SEC)
                continue

            action_id = item.strip()
            raw = r.get(record_key(action_id))
            if not raw:
                reject(action_id, "missing_action_record")
                r.lrem(INFLIGHT_Q, 1, action_id)
                continue

            rec = jload(raw)
            action = rec.get("action") or {}
            action_type = (action.get("type") or "").strip()
            target = (action.get("target") or "").strip()

            if not action_type:
                reject(action_id, "missing_action_type")
                r.lrem(INFLIGHT_Q, 1, action_id)
                continue

            computed = digest_action(action)
            stored = (rec.get("digest") or "").strip()

            if REQUIRE_DIGEST_MATCH:
                if not stored:
                    reject(action_id, "missing_digest")
                    r.lrem(INFLIGHT_Q, 1, action_id)
                    continue
                if stored != computed:
                    reject(action_id, "digest_mismatch")
                    r.lrem(INFLIGHT_Q, 1, action_id)
                    continue

            if should_auto(action_type, target):
                approve(action_id, rec, computed)
            else:
                needs_human(action_id, rec)

            r.lrem(INFLIGHT_Q, 1, action_id)

        except (redis.exceptions.BusyLoadingError,
                redis.exceptions.ConnectionError,
                redis.exceptions.TimeoutError) as e:
            print("redis not ready, retrying:", repr(e), flush=True)
            time.sleep(1)
            continue


if __name__ == "__main__":
    run()
