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
