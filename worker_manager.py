import os
import time
import json
import uuid
import hashlib
import redis
from datetime import datetime, timezone
from ops_digest import digest_action


# -----------------------------
# Config
# -----------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

INCIDENTS_Q = os.getenv("OPS_INCIDENTS_Q", "ops:incidents").strip()
TRIAGED_Q = os.getenv("OPS_INCIDENTS_TRIAGED_Q", "ops:incidents:triaged").strip()
DECISIONS_Q = os.getenv("OPS_MANAGER_DECISIONS_Q", "ops:manager:decisions").strip()
PROPOSED_Q = os.getenv("OPS_PROPOSED_Q", "ops:actions:proposed").strip()

POLL_SEC = float(os.getenv("MANAGER_POLL_SEC", "2").strip() or "2")
DEDUPE_SEC = int(os.getenv("MANAGER_DEDUPE_SEC", "300").strip() or "300")
RATE_LIMIT_SEC = int(os.getenv("MANAGER_RATE_LIMIT_SEC", "30").strip() or "30")

TARGET_COOLDOWN_SEC = int(os.getenv("TARGET_COOLDOWN_SEC", "0").strip() or "0")

ENABLE_PROPOSE = os.getenv("MANAGER_ENABLE_PROPOSE", "0").strip() == "1"
PROPOSE_TTL_SEC = int(os.getenv("MANAGER_PROPOSE_TTL_SEC", "900").strip() or "900")

# Budget gate (optional)
BUDGET_MAX = int(os.getenv("MANAGER_ACTION_BUDGET_MAX", "0").strip() or "0")  # 0 disables
BUDGET_WINDOW_SEC = int(os.getenv("MANAGER_ACTION_BUDGET_WINDOW_SEC", "3600").strip() or "3600")
BUDGET_ZSET = os.getenv("MANAGER_ACTION_BUDGET_ZSET", "ops:budget:actions").strip()

# Global freeze key (optional)
OPS_GLOBAL_FREEZE_KEY = os.getenv("OPS_GLOBAL_FREEZE_KEY", "").strip()

MANAGER_ID = os.getenv("MANAGER_ID", "agent_manager").strip()

r = redis.from_url(REDIS_URL, decode_responses=True)


def now_ts() -> int:
    return int(time.time())


def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def jload(s: str):
    return json.loads(s)


def incident_fingerprint(inc: dict) -> str:
    kind = (inc.get("kind") or "").strip()
    svc = (inc.get("service") or "").strip()
    sev = (inc.get("severity") or "").strip()

    ev = inc.get("evidence") or {}
    url = (ev.get("url") or "").strip()
    status = str(ev.get("status") or "").strip()
    err = (ev.get("error") or "").strip()

    base = f"{svc}|{kind}|{sev}|{url}|{status}|{err[:120]}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def classify_severity(inc: dict) -> str:
    kind = (inc.get("kind") or "").lower()
    if "unreachable" in kind:
        return "critical"
    if "http_error" in kind:
        return "high"
    if "unhealthy" in kind:
        return "high"
    if "exception" in kind:
        return "medium"
    return (inc.get("severity") or "low").lower()


def recommend_action(inc: dict) -> dict:
    sev = classify_severity(inc)
    svc = (inc.get("service") or "sentinel-api").strip()

    if sev in ("critical", "high"):
        return {
            "type": "restart_service",
            "target": svc,
            "reason": f"recommended by manager ({sev})",
            "confidence": 0.85 if sev == "critical" else 0.70,
            "params": {},
        }

    return {
        "type": "none",
        "target": "",
        "reason": "no action recommended",
        "confidence": 0.40,
        "params": {},
    }


def should_suppress(fp: str) -> tuple[bool, str]:
    dedupe_key = f"ops:dedupe:{fp}"
    rl_key = f"ops:ratelimit:{fp}"

    if r.exists(dedupe_key):
        return True, "dedupe"
    r.set(dedupe_key, "1", ex=DEDUPE_SEC)

    if r.exists(rl_key):
        return True, "rate_limit"
    r.set(rl_key, "1", ex=RATE_LIMIT_SEC)

    return False, "emit"


def _global_freeze_active() -> bool:
    if not OPS_GLOBAL_FREEZE_KEY:
        return False
    return bool(r.exists(OPS_GLOBAL_FREEZE_KEY))


def _budget_allows() -> tuple[bool, str]:
    if BUDGET_MAX <= 0:
        return True, "ok"
    ts = now_ts()
    cutoff = ts - BUDGET_WINDOW_SEC

    # Clean old entries
    r.zremrangebyscore(BUDGET_ZSET, 0, cutoff)

    count = r.zcard(BUDGET_ZSET)
    if count >= BUDGET_MAX:
        return False, f"budget_exceeded {count}/{BUDGET_MAX} in {BUDGET_WINDOW_SEC}s"
    return True, "ok"


def _budget_record_event():
    if BUDGET_MAX <= 0:
        return
    ts = now_ts()
    # unique member
    member = f"{ts}:{uuid.uuid4().hex[:8]}"
    r.zadd(BUDGET_ZSET, {member: ts})


def _cooldown_key(action_type: str, target: str) -> str:
    return f"ops:cooldown:{action_type}:{target}"


def propose_from_recommendation(inc: dict, rec: dict, fp: str) -> str | None:
    if not rec:
        return None
    if (rec.get("type") or "") == "none":
        return None

    if _global_freeze_active():
        return None

    ok, why = _budget_allows()
    if not ok:
        return None

    # prevent repeated proposals for same fingerprint during TTL
    fp_key = f"ops:proposed:fp:{fp}"
    if r.exists(fp_key):
        print("propose_suppressed: already proposed for fp", fp[:12], flush=True)
        return None

    action_type = (rec.get("type") or "").strip()
    target = (rec.get("target") or "").strip()

    # target cooldown
    if TARGET_COOLDOWN_SEC > 0:
        cd_key = _cooldown_key(action_type, target)
        if r.exists(cd_key):
            print("propose_suppressed: cooldown active for", action_type, target, flush=True)
            return None
        r.set(cd_key, "1", ex=TARGET_COOLDOWN_SEC)

    action_id = f"act_{now_ts()}_{uuid.uuid4().hex[:6]}"
    incident_id = (inc.get("incident_id") or "").strip() or f"inc_{uuid.uuid4().hex[:8]}"

    record = {
        "action_id": action_id,
        "incident_id": incident_id,
        "created_ts": now_ts(),
        "expires_ts": now_ts() + PROPOSE_TTL_SEC,
        "status": "proposed",
        "fingerprint": fp,
        "action": {
            "type": action_type,
            "target": target,
            "reason": (rec.get("reason") or "").strip(),
            "params": rec.get("params") or {},
        },
        "manager": MANAGER_ID,
        "recommended_confidence": rec.get("confidence", 0.0),
    }

    # canonical digest (shared across manager/approver/executor)
    record["digest"] = digest_action(record["action"])

    r.set(f"ops:action:{action_id}", jdump(record))
    r.rpush(PROPOSED_Q, action_id)

    # mark proposal for fingerprint
    r.set(fp_key, action_id, ex=PROPOSE_TTL_SEC)

    # budget event
    _budget_record_event()

    return action_id


def run():
    print("manager-worker started (decision + optional propose).", flush=True)
    print("REDIS_URL   =", REDIS_URL, flush=True)
    print("INCIDENTS_Q =", INCIDENTS_Q, flush=True)
    print("TRIAGED_Q   =", TRIAGED_Q, flush=True)
    print("DECISIONS_Q =", DECISIONS_Q, flush=True)
    print("PROPOSED_Q  =", PROPOSED_Q, flush=True)
    print("POLL_SEC    =", POLL_SEC, flush=True)
    print("DEDUPE_SEC  =", DEDUPE_SEC, flush=True)
    print("RATE_LIMIT_SEC =", RATE_LIMIT_SEC, flush=True)
    print("TARGET_COOLDOWN_SEC =", TARGET_COOLDOWN_SEC, flush=True)
    print("MANAGER_ACTION_BUDGET_MAX =", BUDGET_MAX, flush=True)
    print("MANAGER_ACTION_BUDGET_WINDOW_SEC =", BUDGET_WINDOW_SEC, flush=True)
    print("OPS_GLOBAL_FREEZE_KEY =", OPS_GLOBAL_FREEZE_KEY, flush=True)
    print("MANAGER_ENABLE_PROPOSE =", ENABLE_PROPOSE, flush=True)
    print("MANAGER_PROPOSE_TTL_SEC =", PROPOSE_TTL_SEC, flush=True)

    while True:
        raw = r.blpop(INCIDENTS_Q, timeout=5)
        if not raw:
            time.sleep(POLL_SEC)
            continue

        _, payload = raw
        ts = now_ts()

        try:
            inc = jload(payload)
        except Exception:
            r.rpush(DECISIONS_Q, jdump({
                "ts": ts,
                "manager": MANAGER_ID,
                "ok": False,
                "error": "invalid_json",
                "raw": (payload or "")[:300],
            }))
            continue

        fp = incident_fingerprint(inc)
        suppress, why = should_suppress(fp)
        sev = classify_severity(inc)
        rec = recommend_action(inc)

        # Always write decision audit record
        r.rpush(DECISIONS_Q, jdump({
            "ts": ts,
            "manager": MANAGER_ID,
            "fingerprint": fp,
            "suppressed": suppress,
            "suppress_reason": why,
            "severity": sev,
            "recommendation": rec,
            "incident_id": inc.get("incident_id"),
            "kind": inc.get("kind"),
            "service": inc.get("service"),
        }))

        # Emit triaged only if not suppressed
        if not suppress:
            triaged = {
                "ts": ts,
                "manager": MANAGER_ID,
                "fingerprint": fp,
                "suppressed": suppress,
                "suppress_reason": why,
                "incident": inc,
                "severity": sev,
                "recommendation": rec,
            }
            r.rpush(TRIAGED_Q, jdump(triaged))
            print("triaged:", inc.get("incident_id"), inc.get("kind"), "sev=", sev, flush=True)

            if ENABLE_PROPOSE:
                aid = propose_from_recommendation(inc, rec, fp)
                if aid:
                    print("proposed:", aid, "->", rec.get("type"), "target=", rec.get("target"), flush=True)

        time.sleep(POLL_SEC)


if __name__ == "__main__":
    run()
