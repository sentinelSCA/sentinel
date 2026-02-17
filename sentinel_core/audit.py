import json
import datetime
from pathlib import Path

LOG_FILE = Path("logs/sentinel_audit.log")


def log_event(command: str, result: dict):
    LOG_FILE.parent.mkdir(exist_ok=True)

    event = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "command": command,
        "decision": result["decision"],
        "risk": result["risk"],
        "reason": result["reason"],
        "policy_version": result["policy_version"],
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
