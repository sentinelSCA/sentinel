import time
import hmac
import hashlib
import json
import os
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Deque, Tuple, List

import base64
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

# Policy + core
from sentinel_rules.policy_v2 import evaluate_command_v2
from sentinel_core.utils import variable_timestamp
from sentinel_core.reputation import (
    load_reputation_db,
    save_reputation_db,
    get_state,
    update_reputation,
)

# Replay DB (sqlite fallback)
from sentinel_core.replay_db import ensure_schema, check_and_set

# Redis reputation helpers (your file: reputation_redis.py)
from reputation_redis import get_rep, apply_outcome

# Agent identity module (your repo file)
from agent_identity import register_agent, get_agent, revoke_agent


# ----------------------------
# Env / constants
# ----------------------------
load_dotenv(dotenv_path=".env")

APP_NAME = "Sentinel Compliance Agent"
POLICY_VERSION = os.getenv("SENTINEL_POLICY_VERSION", "v2")

# HARDENING KNOBS
STRICT_MODE = os.getenv("SENTINEL_STRICT_MODE", "0").strip() == "1"
GLOBAL_FREEZE = os.getenv("SENTINEL_GLOBAL_FREEZE", "0").strip() == "1"

# Security
API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()
SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "").strip()
TIME_WINDOW_SEC = int(os.getenv("SENTINEL_TIME_WINDOW_SEC", "120").strip() or "120")

# Redis replay protection (primary)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()
REPLAY_PREFIX = os.getenv("SENTINEL_REPLAY_PREFIX", "sentinel:replay").strip()

# Rate limiting (per agent)
RATE_LIMIT_MAX = int(os.getenv("SENTINEL_RATE_LIMIT_MAX", "30").strip() or "30")
RATE_LIMIT_WINDOW_SEC = int(os.getenv("SENTINEL_RATE_LIMIT_WINDOW_SEC", "60").strip() or "60")

# Reputation gate thresholds (Redis rep)
REP_AUTO_DENY = float(os.getenv("REP_AUTO_DENY", "0.20").strip() or "0.20")
REP_AUTO_REVIEW = float(os.getenv("REP_AUTO_REVIEW", "0.40").strip() or "0.40")

# SQLite replay DB path (fallback)
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


# STRICT MODE sanity: refuse startup if secrets missing
if STRICT_MODE:
    if not API_KEY:
        raise RuntimeError("SENTINEL_STRICT_MODE=1 but SENTINEL_API_KEY is missing")
    if not SIGNING_SECRET:
        raise RuntimeError("SENTINEL_STRICT_MODE=1 but SENTINEL_SIGNING_SECRET is missing")


# ----------------------------
# Optional Prometheus metrics
# ----------------------------
PROM_ENABLED = False
try:
    from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST  # type: ignore

    PROM_ENABLED = True
    prom_requests_total = Counter("sentinel_requests_total", "Total requests received")
    prom_requests_ok = Counter("sentinel_requests_ok", "Requests completed successfully (200)")
    prom_http_401_total = Counter("sentinel_http_401_total", "Unauthorized responses")
    prom_http_409_total = Counter("sentinel_http_409_total", "Replay detected responses")
    prom_http_429_total = Counter("sentinel_http_429_total", "Rate limited responses")
    prom_http_503_total = Counter("sentinel_http_503_total", "Global freeze responses")
    prom_decision_allow_total = Counter("sentinel_decision_allow_total", "Allow decisions")
    prom_decision_deny_total = Counter("sentinel_decision_deny_total", "Deny decisions")
    prom_decision_review_total = Counter("sentinel_decision_review_total", "Review decisions")
    prom_replay_detected_total = Counter("sentinel_replay_detected_total", "Replays blocked")
    prom_rate_limited_total = Counter("sentinel_rate_limited_total", "Requests blocked by rate limit")
    prom_agents_seen = Gauge("sentinel_agents_seen", "Number of unique agents seen since startup")
except Exception:
    PROM_ENABLED = False

# Fallback text metrics (if prometheus_client not available)
metrics = {
    "requests_total": 0,
    "requests_ok": 0,
    "http_401_total": 0,
    "http_409_total": 0,
    "http_429_total": 0,
    "http_503_total": 0,
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
denied_commands: Dict[str, int] = defaultdict(int)   # ✅ FIX
allowed_commands: Dict[str, int] = defaultdict(int)


def _m_inc(name: str, n: int = 1) -> None:
    if PROM_ENABLED:
        # map names to prom counters
        if name == "requests_total":
            prom_requests_total.inc(n)
        elif name == "requests_ok":
            prom_requests_ok.inc(n)
        elif name == "http_401_total":
            prom_http_401_total.inc(n)
        elif name == "http_409_total":
            prom_http_409_total.inc(n)
        elif name == "http_429_total":
            prom_http_429_total.inc(n)
        elif name == "http_503_total":
            prom_http_503_total.inc(n)
        elif name == "decision_allow_total":
            prom_decision_allow_total.inc(n)
        elif name == "decision_deny_total":
            prom_decision_deny_total.inc(n)
        elif name == "decision_review_total":
            prom_decision_review_total.inc(n)
        elif name == "replay_detected_total":
            prom_replay_detected_total.inc(n)
        elif name == "rate_limited_total":
            prom_rate_limited_total.inc(n)
        return

    metrics[name] = int(metrics.get(name, 0)) + n


def _m_agents_seen_update() -> None:
    if PROM_ENABLED:
        prom_agents_seen.set(len(agents_seen))


# ----------------------------
# Telegram alerts
# ----------------------------
def send_telegram_alert(message: str) -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip().strip('"')
    chat_id = os.getenv("TELEGRAM_ADMIN_CHAT", "").strip().strip('"')

    if not token or not chat_id:
        return

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message[:3500],
            "disable_web_page_preview": True,
        }
        requests.post(url, json=payload, timeout=5)
    except Exception:
        pass


# =========================
# App
# =========================
app = FastAPI(title=APP_NAME, version=POLICY_VERSION)


# ----------------------------
# In-memory rate limiter
# ----------------------------
_rate_events: Dict[str, Deque[float]] = defaultdict(deque)


def _now() -> float:
    return time.time()


def _sign_payload(payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(SIGNING_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _require_api_key(x_api_key: Optional[str]) -> None:
    # In strict mode, API_KEY must be present and must match.
    # In non-strict mode, if API_KEY is empty, we accept.
    if API_KEY and x_api_key != API_KEY:
        _m_inc("http_401_total")
        raise HTTPException(status_code=401, detail="Invalid API key")


def _require_timestamp_window(ts_unix: float) -> None:
    if abs(_now() - ts_unix) > TIME_WINDOW_SEC:
        _m_inc("http_401_total")
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
        _m_inc("http_429_total")
        _m_inc("rate_limited_total")
        ratelimit_by_agent[agent_id] += 1
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    q.append(now)


def _top_items(d: Dict[str, int], n: int = 5) -> List[Tuple[str, int]]:
    return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]


# ----------------------------
# Replay protection (Redis primary, sqlite fallback)
# ----------------------------
_redis = None
_redis_ok = False
try:
    import redis  # type: ignore

    _redis = redis.from_url(REDIS_URL, decode_responses=True)
    _redis.ping()
    _redis_ok = True
except Exception:
    _redis = None
    _redis_ok = False


def _replay_nonce(agent_id: str, command: str, ts_unix: str) -> str:
    raw = f"{agent_id}|{command}|{ts_unix}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _replay_check_and_set(agent_id: str, command: str, ts_unix: str) -> bool:
    """
    Returns True if nonce was NEW and is now stored.
    Returns False if nonce already seen (replay).
    """
    nonce = _replay_nonce(agent_id, command, ts_unix)

    # Redis primary
    if _redis_ok and _redis is not None:
        key = f"{REPLAY_PREFIX}:{nonce}"
        try:
            # SET key "1" NX EX TIME_WINDOW_SEC
            ok = _redis.set(key, "1", nx=True, ex=TIME_WINDOW_SEC)
            return bool(ok)
        except Exception:
            # fall through to sqlite
            pass

    # SQLite fallback
    return bool(check_and_set(DB_PATH, nonce, TIME_WINDOW_SEC))


# ----------------------------
# Audit chain helpers
# ----------------------------
def _audit_hmac(data: str) -> str:
    secret = os.getenv("SENTINEL_AUDIT_SECRET", "").strip()
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


def write_audit_log(request: Request, result: dict) -> None:
    log_dir = os.getenv("SENTINEL_LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)

    audit_path = os.path.join(log_dir, "audit.jsonl")
    state_path = os.path.join(log_dir, "audit.state")
    head_path = os.path.join(log_dir, "audit_head.txt")

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

    entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    chain_input = prev_hash + "|" + entry_json
    entry_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
    sig = _audit_hmac(entry_hash)

    record = dict(entry)
    record["hash"] = entry_hash
    record["sig"] = sig

    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    _write_prev_hash(state_path, entry_hash)
    with open(head_path, "w", encoding="utf-8") as f:
        f.write(entry_hash + "\n")


def get_audit_head() -> dict:
    log_dir = os.getenv("SENTINEL_LOG_DIR", "logs")
    head = _read_prev_hash(os.path.join(log_dir, "audit.state"))
    return {
        "audit_head": head,
        "audit_head_sig": _audit_hmac(head),
    }


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

            entry = {k: rec.get(k) for k in [
                "ts", "client_ip", "agent_id", "command", "decision", "risk",
                "risk_score", "reason", "policy_version", "vt", "prev_hash"
            ]}

            entry_json = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256((prev + "|" + entry_json).encode("utf-8")).hexdigest()

            if rec.get("prev_hash") != prev:
                return {"ok": False, "line": line_no, "error": "prev_hash mismatch"}

            if rec.get("hash") != expected:
                return {"ok": False, "line": line_no, "error": "hash mismatch"}

            secret = os.getenv("SENTINEL_AUDIT_SECRET", "").strip()
            if secret:
                expected_sig = hmac.new(secret.encode("utf-8"), expected.encode("utf-8"), hashlib.sha256).hexdigest()
                if rec.get("sig") != expected_sig:
                    return {"ok": False, "line": line_no, "error": "sig mismatch"}

            prev = rec["hash"]

    return {"ok": True, "lines": line_no}


# ----------------------------
# Models
# ----------------------------
class AnalyzeRequest(BaseModel):
    agent_id: str
    command: str
    timestamp: str
    reputation: float = 0.0  # legacy input


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


class RegisterAgentReq(BaseModel):
    pub_b64: str
    display_name: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RevokeAgentReq(BaseModel):
    agent_id: str
    reason: str = ""


# ----------------------------
# Routes: health/metrics/stats
# ----------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "policy_version": POLICY_VERSION,
        "strict_mode": STRICT_MODE,
        "global_freeze": GLOBAL_FREEZE,
        "replay_backend": "redis" if _redis_ok else "sqlite",
    }


@app.get("/metrics")
def metrics_endpoint():
    if PROM_ENABLED:
        _m_agents_seen_update()
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    # fallback text format
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
    c("sentinel_http_503_total", "Global freeze responses", metrics["http_503_total"])
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
        "strict_mode": STRICT_MODE,
        "global_freeze": GLOBAL_FREEZE,
        "replay_backend": "redis" if _redis_ok else "sqlite",
        "agents_seen": len(agents_seen),
        "top_unauthorized_agents": _top_items(unauthorized_by_agent),
        "top_replay_agents": _top_items(replay_by_agent),
        "top_rate_limited_agents": _top_items(ratelimit_by_agent),
        "top_deny_agents": _top_items(deny_by_agent),
        "top_denied_commands": _top_items(denied_commands),
        "top_allowed_commands": _top_items(allowed_commands),
    }


# ----------------------------
# Routes: audit
# ----------------------------
@app.get("/audit/verify")
def audit_verify():
    return verify_audit_chain()


@app.get("/audit/head")
def audit_head():
    return get_audit_head()


# ----------------------------
# Routes: reputation (Redis)
# ----------------------------
@app.get("/api/v1/rep/{agent_id}")
def rep_status(agent_id: str):
    return {"agent_id": agent_id, "rep": get_rep(agent_id)}


# ----------------------------
# Route: status (signed)
# ----------------------------
@app.get("/api/v1/status/{agent_id}")
def status(
    agent_id: str,
    x_api_key: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    x_timestamp_unix: Optional[str] = Header(default=None),
):
    _require_api_key(x_api_key)

    # In strict mode, signatures must exist
    if SIGNING_SECRET:
        if not x_signature or not x_timestamp_unix:
            _m_inc("http_401_total")
            raise HTTPException(status_code=401, detail="Missing signature headers")

        try:
            ts_unix = float(x_timestamp_unix)
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad X-Timestamp-Unix")

        _require_timestamp_window(ts_unix)

        signed_payload = {"agent_id": agent_id, "ts_unix": x_timestamp_unix}
        expected = _sign_payload(signed_payload)
        if not hmac.compare_digest(expected, x_signature):
            _m_inc("http_401_total")
            raise HTTPException(status_code=401, detail="Bad signature")

    db = load_reputation_db()
    rep_state = get_state(db, agent_id)
    rep_score = get_rep(agent_id)

    q = _rate_events.get(agent_id, [])
    recent = len(q)
    remaining = max(RATE_LIMIT_MAX - recent, 0)

    return {
        "agent_id": agent_id,
        "policy_version": POLICY_VERSION,
        "audit": get_audit_head(),
        "server_time_unix": int(_now()),
        "reputation": rep_state,
        "rep_score": rep_score,
        "rate_limit": {
            "max": RATE_LIMIT_MAX,
            "window_sec": RATE_LIMIT_WINDOW_SEC,
            "recent": recent,
            "remaining": remaining,
        },
    }


# ----------------------------
# Agent Identity (Ed25519) v2
# ----------------------------
@app.post("/api/v2/register")
def api_v2_register(req: RegisterAgentReq, x_api_key: Optional[str] = Header(default=None)):
    _require_api_key(x_api_key)
    return register_agent(req.pub_b64, req.display_name, req.metadata)


@app.get("/api/v2/agent/{agent_id}")
def api_v2_get_agent(agent_id: str, x_api_key: Optional[str] = Header(default=None)):
    _require_api_key(x_api_key)
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post("/api/v2/revoke")
def api_v2_revoke(req: RevokeAgentReq, x_api_key: Optional[str] = Header(default=None)):
    _require_api_key(x_api_key)
    return revoke_agent(req.agent_id, req.reason)


# ----------------------------
# Route: analyze (main)
# ----------------------------
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    req: AnalyzeRequest,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    x_timestamp_unix: Optional[str] = Header(default=None),
):
    _m_inc("requests_total")
    agents_seen.add(req.agent_id)
    _m_agents_seen_update()

    if GLOBAL_FREEZE:
        _m_inc("http_503_total")
        raise HTTPException(status_code=503, detail="Global freeze enabled")

    _rate_limit(req.agent_id)

    # API key auth
    try:
        _require_api_key(x_api_key)
    except HTTPException:
        unauthorized_by_agent[req.agent_id] += 1
        raise

    # Signed mode: require signature headers if secret is set
    if SIGNING_SECRET:
        if not x_signature or not x_timestamp_unix:
            _m_inc("http_401_total")
            unauthorized_by_agent[req.agent_id] += 1
            raise HTTPException(status_code=401, detail="Missing signature headers")

        try:
            ts_unix = float(x_timestamp_unix)
        except ValueError:
            raise HTTPException(status_code=400, detail="Bad X-Timestamp-Unix")

        _require_timestamp_window(ts_unix)

        # Replay check (Redis primary)
        ok_nonce = _replay_check_and_set(req.agent_id, req.command, x_timestamp_unix)
        if not ok_nonce:
            _m_inc("http_409_total")
            _m_inc("replay_detected_total")
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
            _m_inc("http_401_total")
            unauthorized_by_agent[req.agent_id] += 1
            raise HTTPException(status_code=401, detail="Bad signature")

    # Legacy local reputation state
    db = load_reputation_db()
    rep_before = get_state(db, req.agent_id).copy()

    # Policy decision
    decision, risk, score, reason = evaluate_command_v2(req.command, req.reputation)
    decision = str(decision)
    risk = str(risk)
    score = float(score)

    # Redis rep gate (only if policy would allow)
    rep_score_before = get_rep(req.agent_id)
    if decision == "allow":
        if rep_score_before < REP_AUTO_DENY:
            decision = "deny"
            risk = "high"
            score = max(score, 0.95)
            reason = f"Reputation gate: rep={rep_score_before:.2f} < {REP_AUTO_DENY:.2f}"
        elif rep_score_before < REP_AUTO_REVIEW:
            decision = "review"
            risk = "medium"
            score = max(score, 0.65)
            reason = f"Reputation gate: rep={rep_score_before:.2f} < {REP_AUTO_REVIEW:.2f}"

    # Counters
    if decision == "deny":
        deny_by_agent[req.agent_id] += 1
        denied_commands[req.command] += 1
        _m_inc("decision_deny_total")
    elif decision == "allow":
        allowed_commands[req.command] += 1
        _m_inc("decision_allow_total")
    else:
        _m_inc("decision_review_total")

    # Update legacy rep state
    rep_after = update_reputation(db, req.agent_id, decision)
    save_reputation_db(db)

    # Update Redis rep
    rep_score_after = rep_score_before
    try:
        rep_score_after = apply_outcome(req.agent_id, decision)
    except Exception:
        pass

    vt = variable_timestamp(req.command, req.timestamp, req.agent_id)

    body = {
        "timestamp": req.timestamp,
        "agent_id": req.agent_id,
        "command": req.command,
        "decision": decision,
        "risk": risk,
        "reason": reason,
        "risk_score": score,
        "policy_version": POLICY_VERSION,
        "vt": vt,
        "reputation_before": {**rep_before, "rep_score": rep_score_before},
        "reputation_after": {**rep_after, "rep_score": rep_score_after},
    }

    # Telegram alert on deny/review
    try:
        if decision in ("deny", "review"):
            msg = "\n".join([
                "🚨 Sentinel Alert",
                f"Decision: {decision.upper()}",
                f"Agent: {req.agent_id}",
                f"Risk: {risk}",
                f"Command: {(req.command or '')[:200]}",
                f"Reason: {(reason or '')[:300]}",
                f"VT: {body.get('vt','')}",
            ])
            send_telegram_alert(msg)
    except Exception:
        pass

    resp_sig = _sign_payload(body) if SIGNING_SECRET else ""

    _m_inc("requests_ok")

    client_ip = request.client.host if request.client else "unknown"
    log.info(
        "analyze client=%s agent_id=%s decision=%s risk=%s score=%.2f cmd=%s",
        client_ip,
        req.agent_id,
        decision,
        risk,
        float(score),
        (req.command or "")[:200],
    )

    write_audit_log(request, body)
    return AnalyzeResponse(**body, signature=resp_sig)
