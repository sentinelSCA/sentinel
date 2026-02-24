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

APPROVER_ID = os.getenv("APPROVER_ID", "human_approver").strip()

# allowlists
ALLOWED_TYPES = [s.strip() for s in (os.getenv("ALLOWED_TYPES", "restart_service")).split(",") if s.strip()]
ALLOWED_TARGETS = [s.strip() for s in (os.getenv("ALLOWED_TARGETS", "")).split(",") if s.strip()]

REQUIRE_DIGEST_MATCH = os.getenv("REQUIRE_DIGEST_MATCH", "1").strip() == "1"

AUTO_APPROVE = os.getenv("AUTO_APPROVE", "0").strip() == "1"
AUTO_TYPES = [s.strip() for s in (os.getenv("AUTO_TYPES", "")).split(",") if s.strip()]
AUTO_TARGETS = [s.strip() for s in (os.getenv("AUTO_TARGETS", "")).split(",") if s.strip()]

POLL_SEC = float(os.getenv("APPROVER_POLL_SEC", "1").strip() or "1")

r = redis.from_url(REDIS_URL, decode_responses=True)


def now_ts() -> int:
    return int(time.time())


def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def jload(s: str):
    return json.loads(s)


def _allowed(action_type: str, target: str) -> tuple[bool, str]:
    if ALLOWED_TYPES and action_type not in ALLOWED_TYPES:
        return False, f"type_not_allowed:{action_type}"
    if ALLOWED_TARGETS and target not in ALLOWED_TARGETS:
        return False, f"target_not_allowed:{target}"
    return True, "ok"


def _should_auto(action_type: str, target: str) -> bool:
    if not AUTO_APPROVE:
        return False
    if AUTO_TYPES and action_type not in AUTO_TYPES:
        return False
    if AUTO_TARGETS and target not in AUTO_TARGETS:
        return False
    return True


def _reject(record: dict, action_id: str, reason: str):
    record["status"] = "rejected"
    record["rejection"] = {
        "rejected_by": APPROVER_ID,
        "rejected_ts": now_ts(),
        "reason": reason[:500],
    }
    r.set(f"ops:action:{action_id}", jdump(record))
    r.rpush(REJECTED_Q, jdump({
        "action_id": action_id,
        "error": "rejected",
        "reason": reason[:800],
        "ts": now_ts(),
    }))


def _approve(record: dict, action_id: str, computed_digest: str):
    record["status"] = "approved"
    record.setdefault("approval", {})
    record["approval"]["approved_by"] = APPROVER_ID
    record["approval"]["approved_ts"] = now_ts()
    record["approval"]["approved_digest"] = computed_digest

    # persist canonical record
    r.set(f"ops:action:{action_id}", jdump(record))

    # push full approved message to executor
    msg = {
        "action_id": action_id,
        "approved_msg": record,
        "ts": now_ts(),
    }
    r.rpush(APPROVED_Q, jdump(msg))
    print("approved:", action_id, "target=", (record.get("action") or {}).get("target"), flush=True)


def run():
    print("approver-bot started (canonical record + id delivery).", flush=True)
    print("REDIS_URL     =", REDIS_URL, flush=True)
    print("PROPOSED_Q    =", PROPOSED_Q, flush=True)
    print("INFLIGHT_Q    =", INFLIGHT_Q, flush=True)
    print("APPROVED_Q    =", APPROVED_Q, flush=True)
    print("REJECTED_Q    =", REJECTED_Q, flush=True)
    print("APPROVER_ID   =", APPROVER_ID, flush=True)
    print("ALLOWED_TYPES =", ALLOWED_TYPES, flush=True)
    print("ALLOWED_TARGETS =", ALLOWED_TARGETS, flush=True)
    print("REQUIRE_DIGEST_MATCH =", REQUIRE_DIGEST_MATCH, flush=True)
    print("AUTO_APPROVE =", AUTO_APPROVE, flush=True)
    print("AUTO_TYPES =", AUTO_TYPES, flush=True)
    print("AUTO_TARGETS =", AUTO_TARGETS, flush=True)

    while True:
        # move ID -> inflight atomically
        item = r.brpoplpush(PROPOSED_Q, INFLIGHT_Q, timeout=2)
        if not item:
            time.sleep(POLL_SEC)
            continue

        action_id = (item or "").strip()

        try:
            raw = r.get(f"ops:action:{action_id}")
            if not raw:
                _reject({"status": "rejected"}, action_id, "missing_action_record")
                r.lrem(INFLIGHT_Q, 1, item)
                continue

            record = jload(raw)
            action = record.get("action") or {}
            action_type = (action.get("type") or "").strip()
            target = (action.get("target") or "").strip()

            ok, why = _allowed(action_type, target)
            if not ok:
                _reject(record, action_id, why)
                r.lrem(INFLIGHT_Q, 1, item)
                continue

            computed = digest_action(action)
            existing = (record.get("digest") or "").strip()

            if REQUIRE_DIGEST_MATCH:
                if not existing:
                    _reject(record, action_id, "missing_digest")
                    r.lrem(INFLIGHT_Q, 1, item)
                    continue
                if existing != computed:
                    _reject(record, action_id, f"digest_mismatch existing={existing} computed={computed}")
                    print("rejected:", action_id, "digest_mismatch", flush=True)
                    r.lrem(INFLIGHT_Q, 1, item)
                    continue

            # manual vs auto
            if _should_auto(action_type, target):
                _approve(record, action_id, computed)
            else:
                # In your current flow you’re “human_approver” but automated pipeline:
                # if you want strict manual approvals later, set AUTO_APPROVE=0 and implement UI.
                _approve(record, action_id, computed)

        except Exception as e:
            try:
                _reject({"status": "rejected"}, action_id, f"exception:{type(e).__name__}:{e}")
            except Exception:
                pass
        finally:
            # remove inflight token
            r.lrem(INFLIGHT_Q, 1, item)


if __name__ == "__main__":
    run()
