import os
import time
import json
import subprocess
import redis

from ops_digest import digest_action

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

APPROVED_Q = os.getenv("OPS_APPROVED_Q", "ops:actions:approved").strip()
INFLIGHT_Q = os.getenv("OPS_APPROVED_INFLIGHT_Q", "ops:actions:approved:inflight").strip()
EXECUTED_Q = os.getenv("OPS_EXECUTED_Q", "ops:actions:executed").strip()
REJECTED_Q = os.getenv("OPS_REJECTED_Q", "ops:actions:rejected").strip()

EXECUTOR_ID = os.getenv("EXECUTOR_ID", "agent_executor").strip()

ALLOWED_TYPES = [s.strip() for s in (os.getenv("ALLOWED_TYPES", "restart_service")).split(",") if s.strip()]
ALLOWED_TARGETS = [s.strip() for s in (os.getenv("ALLOWED_TARGETS", "")).split(",") if s.strip()]

REQUIRE_DIGEST_MATCH = os.getenv("REQUIRE_DIGEST_MATCH", "1").strip() == "1"
IDEMPOTENCY_TTL_SEC = int(os.getenv("IDEMPOTENCY_TTL_SEC", "86400").strip() or "86400")

COMPOSE_PROJECT_DIR = os.getenv("COMPOSE_PROJECT_DIR", "/app").strip()
COMPOSE_FILE = os.getenv("COMPOSE_FILE", "/app/docker-compose.yml").strip()
COMPOSE_ENV_FILE = os.getenv("COMPOSE_ENV_FILE", "/app/.env").strip()

EXECUTOR_GLOBAL_FREEZE_KEY = os.getenv("EXECUTOR_GLOBAL_FREEZE_KEY", "").strip()
POLL_SEC = float(os.getenv("EXECUTOR_POLL_SEC", "1").strip() or "1")

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


def _save_record(action_id: str, rec: dict):
    ttl = ttl_from_record(rec)
    r.setex(record_key(action_id), ttl, jdump(rec))


def _freeze_active() -> bool:
    if not EXECUTOR_GLOBAL_FREEZE_KEY:
        return False
    return bool(r.exists(EXECUTOR_GLOBAL_FREEZE_KEY))


def _allowed(action_type: str, target: str) -> tuple[bool, str]:
    if ALLOWED_TYPES and action_type not in ALLOWED_TYPES:
        return False, f"type_not_allowed:{action_type}"
    if ALLOWED_TARGETS and target not in ALLOWED_TARGETS:
        return False, f"target_not_allowed:{target}"
    return True, "ok"


def _idempotency_key(action_id: str) -> str:
    return f"ops:exec:done:{action_id}"


def _mark_done_once(action_id: str) -> bool:
    return bool(r.set(_idempotency_key(action_id), "1", nx=True, ex=IDEMPOTENCY_TTL_SEC))


def _run_compose_restart(service: str) -> tuple[int, str, str, str]:
    cmd = ["docker", "compose", "-f", COMPOSE_FILE, "--env-file", COMPOSE_ENV_FILE, "restart", service]
    try:
        p = subprocess.run(
            cmd,
            cwd=COMPOSE_PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=60,
        )
        hint = "env file present" if os.path.exists(COMPOSE_ENV_FILE) else "env file missing"
        return p.returncode, p.stdout or "", p.stderr or "", hint
    except subprocess.TimeoutExpired:
        return 124, "", "timeout executing docker compose", "timeout"
    except Exception as e:
        return 125, "", f"exception:{type(e).__name__}:{e}", "exception"


def _execute_restart_service(action: dict) -> dict:
    target = (action.get("target") or "").strip()
    rc, out, err, hint = _run_compose_restart(target)
    return {
        "claimed_by": EXECUTOR_ID,
        "claimed_ts": now_ts(),
        "executed_ts": now_ts(),
        "ok": (rc == 0),
        "returncode": rc,
        "stdout": out[:4000],
        "stderr": err[:4000],
        "cmd": f"docker compose -f {COMPOSE_FILE} --env-file {COMPOSE_ENV_FILE} restart {target}",
        "compose_mode": "v2",
        "hint": hint,
    }


def _reject(action_id: str, rec: dict, reason: str, extra: dict | None = None):
    rec["status"] = "rejected"
    rec["execution"] = {
        "claimed_by": EXECUTOR_ID,
        "claimed_ts": now_ts(),
        "executed_ts": now_ts(),
        "ok": False,
        "reason": reason[:300],
        "returncode": 1,
        "stdout": "",
        "stderr": (extra or {}).get("stderr", ""),
        "cmd": (extra or {}).get("cmd", ""),
        "compose_mode": "v2",
        "hint": (extra or {}).get("hint", ""),
    }
    _save_record(action_id, rec)

    r.rpush(REJECTED_Q, jdump({
        "action_id": action_id,
        "error": "execution_rejected",
        "reason": reason[:800],
        "extra": extra or {},
        "ts": now_ts(),
    }))


def _record_executed(action_id: str, rec: dict, execution: dict):
    rec["status"] = "executed" if execution.get("ok") else "failed"
    rec["execution"] = execution
    _save_record(action_id, rec)

    if execution.get("ok"):
        r.rpush(EXECUTED_Q, jdump({
            "action_id": action_id,
            "approved_msg": rec,
            "execution": execution,
            "ts": now_ts(),
        }))
    else:
        r.rpush(REJECTED_Q, jdump({
            "action_id": action_id,
            "error": "execution_failed",
            "extra": execution,
            "ts": now_ts(),
        }))


def run():
    print("executor_worker started (canonical record key aligned).", flush=True)
    print("APPROVED_Q  =", APPROVED_Q, flush=True)
    print("INFLIGHT_Q  =", INFLIGHT_Q, flush=True)

    last_freeze_state = None

    while True:
        frozen = _freeze_active()
        if frozen != last_freeze_state:
            print("freeze=" + str(frozen).lower(), flush=True)
            last_freeze_state = frozen

        if frozen:
            time.sleep(1.0)
            continue

        item = r.brpoplpush(APPROVED_Q, INFLIGHT_Q, timeout=2)
        if not item:
            time.sleep(POLL_SEC)
            continue

        try:
            msg = jload(item)
            action_id = (msg.get("action_id") or "").strip()
            rec = msg.get("approved_msg") or {}
            action = rec.get("action") or {}

            if not action_id:
                # can’t do anything
                continue

            ok, why = _allowed((action.get("type") or "").strip(), (action.get("target") or "").strip())
            if not ok:
                _reject(action_id, rec, why, extra={})
                continue

            computed = digest_action(action)
            approved_digest = ((rec.get("approval") or {}).get("approved_digest") or "").strip()

            if REQUIRE_DIGEST_MATCH:
                if not approved_digest:
                    _reject(action_id, rec, "missing_approved_digest", extra={})
                    continue
                if approved_digest != computed:
                    _reject(action_id, rec, f"digest_mismatch approved={approved_digest} computed={computed}", extra={})
                    continue

            if not _mark_done_once(action_id):
                # already done — don’t re-run
                continue

            action_type = (action.get("type") or "").strip()
            target = (action.get("target") or "").strip()

            if action_type == "restart_service":
                execution = _execute_restart_service(action)
                _record_executed(action_id, rec, execution)
                print("executed:", action_id, "rc=", execution.get("returncode"), flush=True)
            else:
                _reject(action_id, rec, f"unsupported_action_type:{action_type}", extra={})

        except Exception as e:
            # best effort: don’t crash the worker loop
            try:
                _reject("unknown", {"action": {}}, f"exception:{type(e).__name__}:{e}", extra={})
            except Exception:
                pass
        finally:
            r.lrem(INFLIGHT_Q, 1, item)


if __name__ == "__main__":
    run()
