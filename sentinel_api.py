import time
import hmac
import hashlib
import json
import os
import logging

from datetime import datetime, timezone

def _to_float(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return float(default)

from collections import defaultdict, deque
from typing import Optional, Dict, Any, Deque, Tuple, List

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from sentinel_rules.policy_v2 import evaluate_command_v2
from sentinel_core.utils import variable_timestamp
from sentinel_core.reputation import (
    load_reputation_db,
    save_reputation_db,
    get_state,
    update_reputation,
)
from sentinel_core.replay_db import ensure_schema, check_and_set

# Load .env from repo root (when running uvicorn from ~/sentinel)
load_dotenv(dotenv_path=".env")

APP_NAME = "Sentinel Compliance Agent"
POLICY_VERSION = os.getenv("SENTINEL_POLICY_VERSION", "v2")

# Security
API_KEY = os.getenv("SENTINEL_API_KEY", "")
SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "")
TIME_WINDOW_SEC = int(os.getenv("SENTINEL_TIME_WINDOW_SEC", "120"))

# Rate limiting (per agent)
RATE_LIMIT_MAX = int(os.getenv("SENTINEL_RATE_LIMIT_MAX", "30"))
RATE_LIMIT_WINDOW_SEC = int(os.getenv("SENTINEL_RATE_LIMIT_WINDOW_SEC", "60"))

# DB path (shared with reputation)
DB_PATH = ensure_schema(os.getenv("SENTINEL_DB_PATH", "sentinel.db"))

# Logging
LOG_DIR = os.getenv("SENTINEL_LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "sentinel_api.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
log = logging.getLogger("sentinel_api")

app = FastAPI(title=APP_NAME, version=POLICY_VERSION)

# ---- In-memory rate limiter (good for single instance) ----
_rate_events: Dict[str, Deque[float]] = defaultdict(deque)

# ---- Metrics / stats (in-memory) ----
metrics = {
    "requests_total": 0,
    "requests_ok": 0,
    "http_401_total": 0,
    "http_409_total": 0,
    "http_429_total": 0,
    "decision_allow_total": 0,
    "decision_deny_total": 0,
    "decision_review_total": 0,
    "replay_detected_total": 0,
    "rate_limited_total": 0,
}
agents_seen: set[str] = set()

unauthorized_by_agent: Dict[str, int] = defaultdict(int)
replay_by_agent: Dict[str, int] = defaultdict(int)
ratelimit_by_agent: Dict[str, int] = defaultdict(int)
deny_by_agent: Dict[str, int] = defaultdict(int)
denied_commands: Dict[str, int] = defaultdict(int)
allowed_commands: Dict[str, int] = defaultdict(int)

def _now() -> float:
    return time.time()

def _sign_payload(payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(SIGNING_SECRET.encode(), msg, hashlib.sha256).hexdigest()

def _require_api_key(x_api_key: Optional[str]) -> None:
    if API_KEY and x_api_key != API_KEY:
        metrics["http_401_total"] += 1
        raise HTTPException(status_code=401, detail="Invalid API key")

def _require_timestamp_window(ts_unix: float) -> None:
    if abs(_now() - ts_unix) > TIME_WINDOW_SEC:
        metrics["http_401_total"] += 1
        raise HTTPException(status_code=401, detail="Timestamp outside allowed window")

def _rate_limit(agent_id: str) -> None:
    if RATE_LIMIT_MAX <= 0:
        return
    now = _now()
    q = _rate_events[agent_id]
    cutoff = now - float(RATE_LIMIT_WINDOW_SEC)
    while q and q[0] < cutoff:
        q.popleft()
    if len(q) >= RATE_LIMIT_MAX:
        metrics["http_429_total"] += 1
        metrics["rate_limited_total"] += 1
        ratelimit_by_agent[agent_id] += 1
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    q.append(now)

def _top_items(d: Dict[str, int], n: int = 5) -> List[Tuple[str, int]]:
    return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]

def _audit_hmac(data: str) -> str:
    secret = os.getenv("SENTINEL_AUDIT_SECRET", "")
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()

def _read_prev_hash(state_path: str) -> str:
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return f.read().strip() or "GENESIS"
    except FileNotFoundError:
        return "GENESIS"

def _write_prev_hash(state_path: str, new_hash: str) -> None:
    with open(state_path, "w", encoding="utf-8") as f:
        f.write(new_hash)

def write_audit_log(request, result: dict):
    log_dir = os.getenv("SENTINEL_LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)

    audit_path = os.path.join(log_dir, "audit.jsonl")
    state_path = os.path.join(log_dir, "audit.state")

    prev_hash = _read_prev_hash(state_path)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "client_ip": getattr(getattr(request, "client", None), "host", None),
        "agent_id": result.get("agent_id"),
        "command": result.get("command"),
        "decision": result.get("decision"),
        "risk": result.get("risk"),
        "risk_score": result.get("risk_score"),
        "reason": result.get("reason"),
        "policy_version": result.get("policy_version"),
        "vt": result.get("vt"),
        "prev_hash": prev_hash,
    }

    # Canonical JSON (stable order) so hash is consistent
    entry_json = json.dumps(entry, ensure_ascii=False, sort_keys=True)

    # Chain hash = sha256(prev_hash + entry_json)
    chain_input = prev_hash + "|" + entry_json
    entry_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    # Optional extra protection: HMAC signature over the chain hash
    sig = _audit_hmac(entry_hash)

    # Final record written to file (still JSONL)
    record = {
        **entry,
        "hash": entry_hash,
        "sig": sig,
    }

    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    _write_prev_hash(state_path, entry_hash)

def verify_audit_chain() -> dict:
    log_dir = os.getenv("SENTINEL_LOG_DIR", "logs")
    audit_path = os.path.join(log_dir, "audit.jsonl")

    if not os.path.exists(audit_path):
        return {"ok": True, "message": "No audit file yet"}

    prev = "GENESIS"
    line_no = 0

    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            line_no += 1
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)

            # Rebuild the exact entry used for hashing (without hash/sig)
            entry = {k: rec.get(k) for k in [
                "ts","client_ip","agent_id","command","decision","risk",
                "risk_score","reason","policy_version","vt","prev_hash"
            ]}

            entry_json = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            expected = hashlib.sha256((prev + "|" + entry_json).encode("utf-8")).hexdigest()

            if rec.get("prev_hash") != prev:
                return {"ok": False, "line": line_no, "error": "prev_hash mismatch"}

            if rec.get("hash") != expected:
                return {"ok": False, "line": line_no, "error": "hash mismatch"}

            # If secret is set, verify signature too
            secret = os.getenv("SENTINEL_AUDIT_SECRET", "")
            if secret:
                expected_sig = hmac.new(secret.encode("utf-8"), expected.encode("utf-8"), hashlib.sha256).hexdigest()
                if rec.get("sig") != expected_sig:
                    return {"ok": False, "line": line_no, "error": "sig mismatch"}

            prev = rec["hash"]

    return {"ok": True, "lines": line_no}

@app.get("/audit/verify")
def audit_verify():
    return verify_audit_chain()

class AnalyzeRequest(BaseModel):
    agent_id: str
    command: str
    timestamp: str
    reputation: float = 0.0

class AnalyzeResponse(BaseModel):
    timestamp: str
    agent_id: str
    command: str
    decision: str
    risk: str
    reason: str
    risk_score: float
    policy_version: str
    vt: str
    reputation_before: Dict[str, Any]
    reputation_after: Dict[str, Any]
    signature: str

@app.get("/health")
def health():
    return {"status": "ok", "policy_version": POLICY_VERSION}

@app.get("/metrics")
def metrics_text():
    # Minimal Prometheus-style output
    lines = []
    def c(name: str, help_text: str, value: int):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")

    c("sentinel_requests_total", "Total requests received", metrics["requests_total"])
    c("sentinel_requests_ok", "Requests completed successfully (200)", metrics["requests_ok"])
    c("sentinel_http_401_total", "Unauthorized responses", metrics["http_401_total"])
    c("sentinel_http_409_total", "Replay detected responses", metrics["http_409_total"])
    c("sentinel_http_429_total", "Rate limited responses", metrics["http_429_total"])
    c("sentinel_decision_allow_total", "Allow decisions", metrics["decision_allow_total"])
    c("sentinel_decision_deny_total", "Deny decisions", metrics["decision_deny_total"])
    c("sentinel_decision_review_total", "Review decisions", metrics["decision_review_total"])
    c("sentinel_replay_detected_total", "Replays blocked", metrics["replay_detected_total"])
    c("sentinel_rate_limited_total", "Requests blocked by rate limit", metrics["rate_limited_total"])

    lines.append("# HELP sentinel_agents_seen Number of unique agents seen since startup")
    lines.append("# TYPE sentinel_agents_seen gauge")
    lines.append(f"sentinel_agents_seen {len(agents_seen)}")

    return "\n".join(lines) + "\n"

@app.get("/stats")
def stats():
    return {
        "policy_version": POLICY_VERSION,
        "agents_seen": len(agents_seen),
        "top_unauthorized_agents": _top_items(unauthorized_by_agent),
        "top_replay_agents": _top_items(replay_by_agent),
        "top_rate_limited_agents": _top_items(ratelimit_by_agent),
        "top_deny_agents": _top_items(deny_by_agent),
        "top_denied_commands": _top_items(denied_commands),
        "top_allowed_commands": _top_items(allowed_commands),
    }

@app.get("/api/v1/status/{agent_id}")
def status(
    agent_id: str,
    x_api_key: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    x_timestamp_unix: Optional[str] = Header(default=None),
):
    # --- Auth (same as analyze) ---
    _require_api_key(x_api_key)

    if SIGNING_SECRET:
        if not x_signature or not x_timestamp_unix:
            raise HTTPException(status_code=401, detail="Missing signature headers")

        try:
            ts_unix = float(x_timestamp_unix)
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad X-Timestamp-Unix")

        _require_timestamp_window(ts_unix)

        signed_payload = {
            "agent_id": agent_id,
            "ts_unix": x_timestamp_unix,
        }

        expected = _sign_payload(signed_payload)
        if not hmac.compare_digest(expected, x_signature):
            raise HTTPException(status_code=401, detail="Bad signature")

    # --- Reputation ---
    db = load_reputation_db()
    rep = get_state(db, agent_id)

    # --- Rate limit info ---
    q = _rate_events.get(agent_id, [])
    recent = len(q)
    remaining = max(RATE_LIMIT_MAX - recent, 0)

    return {
    "agent_id": agent_id,
    "policy_version": POLICY_VERSION,
    "server_time_unix": int(_now()),
    "reputation": rep,

    "last_decision": {
        "decision": rep.get("last_decision"),
        "allowed": rep.get("allowed"),
        "blocked": rep.get("blocked"),
},

    "rate_limit": {
        "max": RATE_LIMIT_MAX,
        "window_sec": RATE_LIMIT_WINDOW_SEC,
        "recent": recent,
        "remaining": remaining,
    },

    "metrics": {
        "requests_total": metrics["requests_total"],
        "requests_ok": metrics["requests_ok"],
        "http_401_total": metrics["http_401_total"],
        "http_409_total": metrics["http_409_total"],
        "http_429_total": metrics["http_429_total"],
    },
}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    req: AnalyzeRequest,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    x_timestamp_unix: Optional[str] = Header(default=None),
):
    metrics["requests_total"] += 1
    agents_seen.add(req.agent_id)

    _rate_limit(req.agent_id)

    # API key auth
    try:
        _require_api_key(x_api_key)
    except HTTPException:
        unauthorized_by_agent[req.agent_id] += 1
        raise

    # Signed mode (recommended): require signature headers if secret is set
    if SIGNING_SECRET:
        if not x_signature or not x_timestamp_unix:
            metrics["http_401_total"] += 1
            unauthorized_by_agent[req.agent_id] += 1
            raise HTTPException(status_code=401, detail="Missing signature headers")

        try:
            ts_unix = float(x_timestamp_unix)
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad X-Timestamp-Unix")

        _require_timestamp_window(ts_unix)

        # Durable replay check (SQLite)
        nonce = hashlib.sha256(f"{req.agent_id}|{req.command}|{x_timestamp_unix}".encode()).hexdigest()
        ok = check_and_set(DB_PATH, nonce, TIME_WINDOW_SEC)
        if not ok:
            metrics["http_409_total"] += 1
            metrics["replay_detected_total"] += 1
            replay_by_agent[req.agent_id] += 1
            raise HTTPException(status_code=409, detail="Replay detected")

        # Verify signature
        signed_payload = {
            "agent_id": req.agent_id,
            "command": req.command,
            "timestamp": req.timestamp,
            "ts_unix": x_timestamp_unix,
        }
        expected = _sign_payload(signed_payload)
        if not hmac.compare_digest(expected, x_signature):
            metrics["http_401_total"] += 1
            unauthorized_by_agent[req.agent_id] += 1
            raise HTTPException(status_code=401, detail="Bad signature")

    # Reputation
    db = load_reputation_db()
    rep_before = get_state(db, req.agent_id).copy()

    decision, risk, score, reason = evaluate_command_v2(req.command, req.reputation)

    if str(decision) == "deny":
        deny_by_agent[req.agent_id] += 1
        denied_commands[req.command] += 1
        metrics["decision_deny_total"] += 1
    elif str(decision) == "allow":
        allowed_commands[req.command] += 1
        metrics["decision_allow_total"] += 1
    else:
        metrics["decision_review_total"] += 1

    rep_after = update_reputation(db, req.agent_id, str(decision))
    save_reputation_db(db)

    vt = variable_timestamp(req.command, req.timestamp, req.agent_id)

    body = {
        "timestamp": req.timestamp,
        "agent_id": req.agent_id,
        "command": req.command,
        "decision": str(decision),
        "risk": str(risk),
        "reason": reason,
        "risk_score": float(score),
        "policy_version": POLICY_VERSION,
        "vt": vt,
        "reputation_before": rep_before,
        "reputation_after": rep_after,
    }

    resp_sig = _sign_payload(body) if SIGNING_SECRET else ""
    metrics["requests_ok"] += 1

    client_ip = request.client.host if request.client else "unknown"
    log.info(
        "analyze client=%s agent_id=%s decision=%s risk=%s score=%.2f cmd=%s",
        client_ip,
        req.agent_id,
        str(decision),
        str(risk),
        float(score),
        req.command[:200],
    )

    write_audit_log(request, body)
    return AnalyzeResponse(**body, signature=resp_sig)
