#!/usr/bin/env python3
import os
import sys
import json
import time
import hmac
import hashlib
from typing import Dict, Any, Tuple

from dotenv import load_dotenv
import requests

load_dotenv(dotenv_path=".env")

API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000/analyze")
API_KEY = os.getenv("SENTINEL_API_KEY", "")
SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "")
TIMEOUT_SECS = int(os.getenv("SENTINEL_HTTP_TIMEOUT", "10"))

# ---------- LOCAL RULES (fallback only) ----------
HIGH_RISK_PATTERNS = [
    "rm -rf",
    "rm -fr",
    "rm -f",
    "rm -r",
    "mkfs",
    "dd ",
    ":(){",          # fork bomb
    "shutdown",
    "reboot",
    "poweroff",
    "init 0",
    "init 6",
    "kill -9",
]

def local_evaluate(command: str) -> Tuple[str, str, str, float]:
    c = (command or "").strip().lower()
    if not c:
        return ("review", "medium", "Empty command", 0.5)

    for p in HIGH_RISK_PATTERNS:
        if p in c:
            return ("deny", "high", f"Matched high-risk pattern: '{p}'", 0.95)

    return ("allow", "low", "No policy violations detected", 0.05)

def _sign_payload(payload: dict) -> str:
    """
    Must match server signing:
    json.dumps(sort_keys=True, separators=(",", ":"))
    """
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(SIGNING_SECRET.encode(), msg, hashlib.sha256).hexdigest()

def call_api(command: str, agent_id: str) -> Dict[str, Any]:
    payload_body = {
        "agent_id": agent_id,
        "command": command,
        "timestamp": "123",
    }

    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY

    # If signing is enabled on the server, include signature headers
    if SIGNING_SECRET:
        ts_unix = str(int(time.time()))
        signed_payload = {
            "agent_id": agent_id,
            "command": command,
            "timestamp": "123",
            "ts_unix": ts_unix,   # IMPORTANT: string
        }
        headers["X-Timestamp-Unix"] = ts_unix
        headers["X-Signature"] = _sign_payload(signed_payload)

    try:
        r = requests.post(API_URL, json=payload_body, headers=headers, timeout=TIMEOUT_SECS)
        data = r.json() if r.content else {}
        data["_status_code"] = r.status_code
        return data
    except Exception as e:
        decision, risk, reason, score = local_evaluate(command)
        return {
            "_status_code": 0,
            "agent_id": agent_id,
            "command": command,
            "decision": decision,
            "risk": risk,
            "reason": f"(local fallback) {reason} | api_error={e}",
            "risk_score": score,
            "timestamp": "123",
            "policy_version": os.getenv("SENTINEL_POLICY_VERSION", "v2"),
            "vt": "",
            "signature": "",
        }

def exit_code_for(decision: str) -> int:
    d = (decision or "").lower()
    if d == "allow":
        return 0
    if d == "deny":
        return 2
    if d == "review":
        return 3
    return 1

def main():
    if len(sys.argv) < 2:
        print("Usage: sentinel_guard.py \"<command>\" [agent_id]")
        sys.exit(1)

    command = sys.argv[1]
    agent_id = sys.argv[2] if len(sys.argv) >= 3 else "guard:local"

    data = call_api(command, agent_id)

    print(json.dumps(data, indent=2, sort_keys=True))
    sys.exit(exit_code_for(data.get("decision", "")))

if __name__ == "__main__":
    main()
