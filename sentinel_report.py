import time
import uuid
from typing import Any, Dict, Optional


def iso_now(ts: Optional[float] = None) -> str:
    if ts is None:
        ts = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def build_action_report(
    *,
    agent_id: str,
    identity: str,
    capability: str,
    action: Dict[str, Any],
    decision: str,
    policy_version: str,
    risk_score: float,
    reason: str,
    action_hash: str,
    previous_hash: str = "",
    approved_by: str = "system-policy",
    environment: str = "production",
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    if not timestamp:
        timestamp = iso_now()

    return {
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "agent": agent_id,
        "identity": identity,
        "environment": environment,
        "capability": capability,
        "action": action,
        "decision": str(decision).upper(),
        "approved_by": approved_by,
        "policy_version": policy_version,
        "risk_score": float(risk_score),
        "reason": reason,
        "timestamp": timestamp,
        "action_hash": action_hash,
        "previous_hash": previous_hash,
    }
