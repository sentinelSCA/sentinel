import re
from enum import Enum

class Decision(str, Enum):
    APPROVED = "APPROVED"
    WARN = "WARN"
    BLOCKED = "BLOCKED"

class Risk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

HIGH_RISK_PATTERNS = [
    r"rm\s+-rf\s+/",
    r":\(\)\s*\{\s*:\|\:\s*&\s*\}\s*;\s*:",  # fork bomb
]

ELEVATED_KEYWORDS = ["sudo", "chmod 777", "dd if=", "mkfs", "shutdown", "reboot"]

def evaluate_command(cmd: str):
    cmd = (cmd or "").strip()

    for pat in HIGH_RISK_PATTERNS:
        if re.search(pat, cmd):
            return Decision.BLOCKED, Risk.CRITICAL, f"Command matches high-risk pattern: {cmd}"

    for kw in ELEVATED_KEYWORDS:
        if kw in cmd:
            return Decision.WARN, Risk.MEDIUM, f"Command contains elevated keyword: {kw}"

    if cmd == "":
        return Decision.WARN, Risk.LOW, "Empty command"

    return Decision.APPROVED, Risk.LOW, "No policy violations detected"
