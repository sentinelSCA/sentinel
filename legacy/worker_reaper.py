import os
import time
import json
import redis
from datetime import datetime, timezone

# -----------------------------
# Config
# -----------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

POLL_SEC = float(os.getenv("REAPER_POLL_SEC", "5").strip() or "5")
STALE_SEC = int(os.getenv("REAPER_INFLIGHT_STALE_SEC", "60").strip() or "60")
MAX_REQUEUES = int(os.getenv("REAPER_MAX_REQUEUES", "5").strip() or "5")

# Queues (defaults match your stack)
PROPOSED_Q = os.getenv("OPS_PROPOSED_Q", "ops:actions:proposed").strip()
PROPOSED_INFLIGHT_Q = os.getenv("OPS_PROPOSED_INFLIGHT_Q", "ops:actions:proposed:inflight").strip()

APPROVED_Q = os.getenv("OPS_APPROVED_Q", "ops:actions:approved").strip()
APPROVED_INFLIGHT_Q = os.getenv("OPS_APPROVED_INFLIGHT_Q", "ops:actions:approved:inflight").strip()

QUARANTINE_Q = os.getenv("OPS_QUARANTINE_Q", "ops:actions:quarantine").strip()

# where canonical action JSON is stored
ACTION_KEY_PREFIX = os.getenv("OPS_ACTION_KEY_PREFIX", "ops:action:").strip()

r = redis.from_url(REDIS_URL, decode_responses=True)

# -----------------------------
# Helpers
# -----------------------------
def now_ts() -> int:
    return int(time.time())

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_json_load(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None

def get_action(action_id: str):
    raw = r.get(f"{ACTION_KEY_PREFIX}{action_id}")
    if not raw:
        return None
    return safe_json_load(raw)

def save_action(action_id: str, rec: dict):
    r.set(f"{ACTION_KEY_PREFIX}{action_id}", json.dumps(rec, separators=(",", ":"), sort_keys=True, ensure_ascii=False))

def requeue_or_quarantine(action_id: str, rec: dict, origin: str):
    """
    origin: "proposed" or "approved"
    """
    rec.setdefault("reaper", {})
    rec["reaper"]["last_seen_inflight_ts"] = now_ts()
    rec["reaper"]["last_seen_inflight_iso"] = iso_now()

    # count requeues per-stage
    key = f"ops:requeue_count:{origin}:{action_id}"
    count = int(r.incr(key))
    # keep this key around for 2 days
    r.expire(key, 172800)

    if count > MAX_REQUEUES:
        rec["status"] = "quarantined"
        rec["reaper"]["quarantined_reason"] = f"max_requeues_exceeded:{MAX_REQUEUES}"
        rec["reaper"]["quarantined_from"] = origin
        rec["reaper"]["quarantined_at"] = iso_now()
        save_action(action_id, rec)
        r.rpush(QUARANTINE_Q, action_id)
        print(f"quarantine: {action_id} from={origin} count={count}", flush=True)
        return

    # requeue to main queue
    save_action(action_id, rec)
    if origin == "proposed":
        r.rpush(PROPOSED_Q, action_id)
    else:
        r.rpush(APPROVED_Q, action_id)

    print(f"requeue: {action_id} from={origin} count={count}", flush=True)

def scan_inflight(inflight_q: str, origin: str):
    """
    inflight_q holds action_ids (strings).
    We requeue if:
      - action record exists
      - status is still waiting (proposed/approved)
      - last claimed_ts is too old
    """
    # small batches; list length can be large later
    n = r.llen(inflight_q)
    if n <= 0:
        return

    # limit work per tick
    limit = min(n, 50)
    ids = r.lrange(inflight_q, 0, limit - 1)
    if not ids:
        return

    for action_id in ids:
        action_id = (action_id or "").strip()
        if not action_id:
            continue

        rec = get_action(action_id)
        if not rec:
            # nothing to recover; drop inflight entry
            try:
                r.lrem(inflight_q, 0, action_id)
            except Exception:
                pass
            continue

        # Determine staleness based on claimed_ts (if present)
        claimed_ts = None
        if isinstance(rec.get("execution"), dict):
            claimed_ts = rec["execution"].get("claimed_ts")
        if claimed_ts is None and isinstance(rec.get("approval"), dict):
            claimed_ts = rec["approval"].get("approved_ts")

        try:
            claimed_ts = int(claimed_ts) if claimed_ts is not None else None
        except Exception:
            claimed_ts = None

        # If no timestamps, treat as stale
        is_stale = True
        if claimed_ts is not None:
            is_stale = (now_ts() - claimed_ts) >= STALE_SEC

        # If already executed/failed/rejected/quarantined, remove inflight entry
        status = (rec.get("status") or "").lower()
        if status in ("executed", "failed", "rejected", "quarantined"):
            r.lrem(inflight_q, 0, action_id)
            continue

        if not is_stale:
            continue

        # stale: remove from inflight and requeue/quarantine
        r.lrem(inflight_q, 0, action_id)
        requeue_or_quarantine(action_id, rec, origin)

def main():
    print("reaper-worker started (inflight recovery).", flush=True)
    print("REDIS_URL =", REDIS_URL, flush=True)
    print("POLL_SEC =", POLL_SEC, flush=True)
    print("STALE_SEC =", STALE_SEC, flush=True)
    print("MAX_REQUEUES =", MAX_REQUEUES, flush=True)
    print("PROPOSED_INFLIGHT_Q =", PROPOSED_INFLIGHT_Q, flush=True)
    print("APPROVED_INFLIGHT_Q =", APPROVED_INFLIGHT_Q, flush=True)
    print("QUARANTINE_Q =", QUARANTINE_Q, flush=True)

    while True:
        try:
            # heartbeat
            r.set("ops:reaper:heartbeat", iso_now(), ex=30)

            # recover inflight
            scan_inflight(PROPOSED_INFLIGHT_Q, "proposed")
            scan_inflight(APPROVED_INFLIGHT_Q, "approved")

        except Exception as e:
            print("reaper error:", repr(e), flush=True)

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
