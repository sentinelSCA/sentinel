from sentinel_core.decision import Decision, Risk
from sentinel_rules.core_rules import HIGH_RISK_COMMANDS, MEDIUM_RISK_KEYWORDS

POLICY_VERSION = "v1"


def evaluate(command: str) -> dict:
    cmd = command.lower()

    # High risk — hard block
    for bad in HIGH_RISK_COMMANDS:
        if bad in cmd:
            return {
                "decision": Decision.BLOCKED,
                "risk": Risk.CRITICAL,
                "reason": f"Command matches high-risk pattern: {bad}",
                "policy_version": POLICY_VERSION,
            }

    # Medium risk — warn
    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in cmd:
            return {
                "decision": Decision.WARN,
                "risk": Risk.MEDIUM,
                "reason": f"Command contains elevated keyword: {keyword}",
                "policy_version": POLICY_VERSION,
            }

    # Default safe
    return {
        "decision": Decision.APPROVED,
        "risk": Risk.LOW,
        "reason": "No policy violations detected",
        "policy_version": POLICY_VERSION,
    }
