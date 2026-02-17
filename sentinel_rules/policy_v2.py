import os
import re
from typing import Tuple

POLICY_VERSION = "v2"

# ---- Reputation thresholds (production defaults) ----
REP_DENY_AT = int(os.getenv("SENTINEL_REP_DENY_AT", "-10"))     # deny all
REP_REVIEW_AT = int(os.getenv("SENTINEL_REP_REVIEW_AT", "-5"))  # force review

# ---- Deny patterns ----
DENY_PATTERNS = [
    # dd wipe pattern (destructive write)
    (re.compile(r"\bdd\b.*\bif=/dev/zero\b.*\bof=/dev/\S+", re.IGNORECASE),
     r"Matched high-risk pattern: 'dd if=/dev/zero of=/dev/*'"),

    # mkfs / wipefs (disk destructive)
    (re.compile(r"\bmkfs(\.\w+)?\b", re.IGNORECASE),
     "Matched high-risk pattern: 'mkfs'"),
    (re.compile(r"\bwipefs\b", re.IGNORECASE),
     "Matched high-risk pattern: 'wipefs'"),

    # rm -rf (core catastrophic delete)
    (re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
     "Matched high-risk pattern: 'rm -rf'"),
    (re.compile(r"\brm\s+-f\s+/\s*$", re.IGNORECASE),
     r"Matched high-risk pattern: '\brm\s+-f\s+/\s*$'"),
    (re.compile(r"\brm\s+-f\s+/\*\s*$", re.IGNORECASE),
     r"Matched high-risk pattern: '\brm\s+-f\s+/\*\s*$'"),
    (re.compile(r"\brm\s+-rf\b.*--no-preserve-root\b", re.IGNORECASE),
     "Matched high-risk pattern: 'rm -rf --no-preserve-root'"),

    # chmod/chown bombs on root
    (re.compile(r"\bchmod\b.*\s-R\s+777\s+/\s*$", re.IGNORECASE),
     "Matched high-risk pattern: 'chmod -R 777 /'"),
    (re.compile(r"\bchown\b.*\s-R\s+\S+\s+/\s*$", re.IGNORECASE),
     "Matched high-risk pattern: 'chown -R * /'"),
]

# ---- Commands requiring human approval ----
REQUIRE_APPROVAL = [
    s.strip().lower()
    for s in os.getenv("SENTINEL_REQUIRE_APPROVAL", "").split(",")
    if s.strip()
]

def evaluate_command_v2(command: str, reputation: int) -> Tuple[str, str, float, str]:
    """
    Returns: (decision, risk, risk_score, reason)
    decision: allow | deny | review
    """

    cmd = (command or "").strip()

    # 1) Reputation gate first (overrides everything)
    if reputation <= REP_DENY_AT:
        return ("deny", "high", 0.99, f"Reputation too low (<= {REP_DENY_AT})")

    if reputation <= REP_REVIEW_AT:
        return ("review", "medium", 0.60, f"Reputation low (<= {REP_REVIEW_AT})")

    # 2) Pattern-based hard denies
    for rx, reason in DENY_PATTERNS:
        if rx.search(cmd):
            return ("deny", "high", 0.95, reason)

    # 3) Default allow
    return ("allow", "low", 0.05, "No policy violations detected")
