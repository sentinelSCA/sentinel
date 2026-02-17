import json
import os
import time
from typing import Any, Dict

# Reputation DB file (simple + durable)
REPUTATION_DB_PATH = os.getenv("SENTINEL_REPUTATION_DB", "reputation.json")

# Decay settings:
# - Every DECAY_PERIOD_SEC, reputation moves STEP toward 0 (so -10 -> -9 -> ... -> 0)
DECAY_PERIOD_SEC = int(os.getenv("SENTINEL_REP_DECAY_PERIOD_SEC", "3600"))  # 1 hour
DECAY_STEP = int(os.getenv("SENTINEL_REP_DECAY_STEP", "1"))                # move by 1

def _now() -> float:
    return time.time()

def _decay_value(rep: int, elapsed_sec: float) -> int:
    """Move reputation toward 0 over time, in discrete steps."""
    if DECAY_PERIOD_SEC <= 0 or DECAY_STEP <= 0:
        return rep

    steps = int(elapsed_sec // DECAY_PERIOD_SEC)
    if steps <= 0:
        return rep

    if rep > 0:
        rep = max(0, rep - steps * DECAY_STEP)
    elif rep < 0:
        rep = min(0, rep + steps * DECAY_STEP)
    return rep

def _apply_decay(state: Dict[str, Any]) -> Dict[str, Any]:
    """Apply decay in-place based on updated_at."""
    updated_at = float(state.get("updated_at", 0.0) or 0.0)
    if updated_at <= 0:
        # first time; nothing to decay yet
        return state

    elapsed = _now() - updated_at
    if elapsed <= 0:
        return state

    rep = int(state.get("reputation", 0) or 0)
    decayed = _decay_value(rep, elapsed)

    if decayed != rep:
        state["reputation"] = decayed
        # IMPORTANT: bump updated_at so we don't keep decaying the same elapsed window repeatedly
        state["updated_at"] = _now()

    return state

def load_reputation_db() -> Dict[str, Any]:
    """Load db from JSON file. If missing, return empty db."""
    if not os.path.exists(REPUTATION_DB_PATH):
        return {"_meta": {"version": 1}, "agents": {}}

    try:
        with open(REPUTATION_DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        # If file is corrupted, fail safe to empty (you can also raise)
        db = {"_meta": {"version": 1}, "agents": {}}

    if "agents" not in db or not isinstance(db["agents"], dict):
        db["agents"] = {}

    return db

def save_reputation_db(db: Dict[str, Any]) -> None:
    tmp = REPUTATION_DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, sort_keys=True)
    os.replace(tmp, REPUTATION_DB_PATH)

def get_state(db: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
    agents = db.setdefault("agents", {})
    state = agents.get(agent_id)

    if not state:
        state = {
            "agent_id": agent_id,
            "reputation": 0,
            "allowed": 0,
            "blocked": 0,
            "reviewed": 0,
            "last_decision": "unknown",
            "updated_at": _now(),
        }
        agents[agent_id] = state

    # Apply decay on read
    _apply_decay(state)
    return state

def update_reputation(db: Dict[str, Any], agent_id: str, decision: str) -> Dict[str, Any]:
    """
    Apply decay first, then update counters and reputation based on decision.
    allow  -> +1
    deny   -> -2
    review -> -1 (soft penalty)
    """
    state = get_state(db, agent_id)

    decision = (decision or "").lower().strip()

    if decision == "allow":
        state["allowed"] = int(state.get("allowed", 0) or 0) + 1
        state["reputation"] = int(state.get("reputation", 0) or 0) + 1
        state["last_decision"] = "allow"

    elif decision == "deny":
        state["blocked"] = int(state.get("blocked", 0) or 0) + 1
        state["reputation"] = int(state.get("reputation", 0) or 0) - 2
        state["last_decision"] = "deny"

    else:
        # review / unknown
        state["reviewed"] = int(state.get("reviewed", 0) or 0) + 1
        state["reputation"] = int(state.get("reputation", 0) or 0) - 1
        state["last_decision"] = "review"

    state["updated_at"] = _now()
    return state
