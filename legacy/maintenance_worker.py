import os
import time
import json
import urllib.request
import urllib.error
import redis

# -----------------------------
# Config
# -----------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "http://sentinel-api:8001").strip()
SENTINEL_ANALYZE_URL = os.getenv("SENTINEL_URL", "http://sentinel-api:8001/analyze").strip()
SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

POLL_SEC = int(os.getenv("MAINT_POLL_SEC", "15").strip() or "15")
MAINT_AGENT_ID = os.getenv("MAINT_AGENT_ID", "agent_maintenance").strip()

INCIDENTS_Q = os.getenv("OPS_INCIDENTS_Q", "ops:incidents").strip()
PROPOSED_Q = os.getenv("OPS_PROPOSED_Q", "ops:actions:proposed").strip()

# Canonical action record key prefix
ACTION_KEY_PREFIX = os.getenv("OPS_ACTION_KEY_PREFIX", "ops:action:").strip()

# If enabled, we try to attach Sentinel decision, but MUST NOT block proposing if Sentinel is down.
REQUIRE_SENTINEL_APPROVAL = os.getenv("MAINT_REQUIRE_SENTINEL_APPROVAL", "1").strip() == "1"

HTTP_TIMEOUT = int(os.getenv("SENTINEL_HTTP_TIMEOUT", "10").strip() or "10")
PROPOSE_TTL_SEC = int(os.getenv("MAINT_PROPOSE_TTL_SEC", "900").strip() or "900")  # 15 min

r = redis.from_url(REDIS_URL, decode_responses=True)

# -----------------------------
# Helpers
# -----------------------------
def now_ts() -> int:
    return int(time.time())

def log(*args):
    print(*args, flush=True)

def http_get_json(url: str, timeout: int = 5) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)

def sentinel_analyze(command: str) -> dict:
    payload = {
        "agent_id": MAINT_AGENT_ID,
        "command": command,
        "timestamp": str(now_ts()),
        "reputation": 0.0,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if SENTINEL_API_KEY:
        headers["X-API-Key"] = SENTINEL_API_KEY

    req = urllib.request.Request(SENTINEL_ANALYZE_URL, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))

def push_incident(kind: str, severity: str, evidence: dict) -> str:
    incident_id = f"inc_{now_ts()}_{int(time.time_ns()%1_000_000)}"
    incident = {
        "incident_id": incident_id,
        "ts": now_ts(),
        "service": "sentinel-api",
        "kind": kind,
        "severity": severity,
        "evidence": evidence,
    }
    r.rpush(INCIDENTS_Q, json.dumps(incident, separators=(",", ":"), sort_keys=True))
    return incident_id

def propose_restart_action(incident_id: str, reason: str) -> str:
    action_id = f"act_{now_ts()}_{int(time.time_ns()%1_000_000)}"
    created = now_ts()
    record = {
        "action_id": action_id,
        "incident_id": incident_id,
        "created_ts": created,
        "status": "proposed",
        "expires_ts": created + PROPOSE_TTL_SEC,
        "action": {
            "type": "restart_service",
            "target": "sentinel-api",
            "params": {},
            "reason": reason,
        },
    }

    # Attach Sentinel decision if possible, but NEVER block proposing.
    if REQUIRE_SENTINEL_APPROVAL:
        try:
            record["sentinel_decision"] = sentinel_analyze(
                f'ops.restart service=sentinel-api reason="{reason}"'
            )
        except Exception as e:
            record["sentinel_decision_error"] = f"{type(e).__name__}: {str(e)[:200]}"

    # Canonical truth
    r.set(ACTION_KEY_PREFIX + action_id, json.dumps(record, separators=(",", ":"), sort_keys=True), ex=PROPOSE_TTL_SEC)

    # ID-only delivery
    r.lpush(PROPOSED_Q, action_id)
    return action_id

# -----------------------------
# Main loop
# -----------------------------
def run():
    log("maintenance_worker started (canonical action record).")
    log("API_BASE_URL =", API_BASE_URL)
    log("SENTINEL_URL  =", SENTINEL_ANALYZE_URL)
    log("REDIS_URL     =", REDIS_URL)
    log("INCIDENTS_Q   =", INCIDENTS_Q)
    log("PROPOSED_Q    =", PROPOSED_Q)
    log("POLL_SEC      =", POLL_SEC)
    log("REQUIRE_SENTINEL_APPROVAL =", REQUIRE_SENTINEL_APPROVAL)
    log("PROPOSE_TTL_SEC =", PROPOSE_TTL_SEC)

    while True:
        try:
            try:
                health = http_get_json(f"{API_BASE_URL}/health", timeout=5)
                if health.get("status") != "ok":
                    inc_id = push_incident(
                        kind="api_unhealthy",
                        severity="high",
                        evidence={"health": health},
                    )
                    aid = propose_restart_action(inc_id, f"health status={health.get('status')}")
                    log("proposed:", aid, "reason=unhealthy")
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                inc_id = push_incident(
                    kind="api_health_http_error",
                    severity="high",
                    evidence={"status": e.code, "body": body[:800], "url": f"{API_BASE_URL}/health"},
                )
                aid = propose_restart_action(inc_id, f"/health HTTP {e.code}")
                log("proposed:", aid, "reason=http_error", e.code)
            except urllib.error.URLError as e:
                inc_id = push_incident(
                    kind="api_unreachable",
                    severity="high",
                    evidence={"error": str(e)[:300], "url": f"{API_BASE_URL}/health"},
                )
                aid = propose_restart_action(inc_id, "api unreachable")
                log("proposed:", aid, "reason=unreachable")
        except Exception as e:
            push_incident(
                kind="maintenance_exception",
                severity="medium",
                evidence={"error": f"{type(e).__name__}: {str(e)[:500]}"},
            )

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    run()

