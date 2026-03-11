import os
import re
import json
from pathlib import Path
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

POLICY_FILE = os.getenv("SENTINEL_POLICY_FILE", "policies/policy.validator.json")

def _load_validator_policy() -> dict | None:
    try:
        return json.loads(Path(POLICY_FILE).read_text())
    except Exception:
        return None

def _match_validator_rule(rule: dict, cmd_type: str | None, target: str | None) -> bool:
    match = rule.get("match") or {}

    rule_type = match.get("type")
    if rule_type is not None and cmd_type != rule_type:
        return False

    target_in = match.get("target_in")
    if target_in is not None and target not in target_in:
        return False

    return True

def _evaluate_validator_policy(cmd_type: str | None, target: str | None):
    policy = _load_validator_policy()
    if not policy:
        return None

    for rule in policy.get("rules", []):
        if _match_validator_rule(rule, cmd_type, target):
            decision = str(rule.get("decision", "deny"))
            risk = str(rule.get("risk", "high"))
            reason = str(rule.get("reason", "Matched validator policy rule."))
            score = 0.05 if decision == "allow" else 0.90 if decision == "review" else 0.95
            return (decision, risk, score, reason)

    defaults = policy.get("defaults") or {}
    if defaults:
        decision = str(defaults.get("decision", "deny"))
        risk = str(defaults.get("risk", "high"))
        reason = str(defaults.get("reason", "Command not allowed by validator policy."))
        score = 0.05 if decision == "allow" else 0.90 if decision == "review" else 0.95
        return (decision, risk, score, reason)

    return None

def evaluate_command_v2(command: str, reputation: int) -> Tuple[str, str, float, str]:
    """
    Returns: (decision, risk, risk_score, reason)
    decision: allow | deny | review
    """

    cmd = (command or "").strip()

# ===============================
    # VALIDATOR EDITION HARD LOCK
    # ===============================

    try:
        import json
        parsed = json.loads(cmd)
        cmd_type = parsed.get("type")
        target = parsed.get("target")
    except Exception:
        cmd_type = None
        target = None

    policy_result = _evaluate_validator_policy(cmd_type, target)
    if policy_result is not None:
        return policy_result

    # 1) Reputation gate first (overrides everything)
    if reputation <= REP_DENY_AT:
        return ("deny", "high", 0.99, f"Reputation too low (<= {REP_DENY_AT})")

    if reputation <= REP_REVIEW_AT:
        return ("review", "medium", 0.60, f"Reputation low (<= {REP_REVIEW_AT})")

    # 2) Pattern-based hard denies
    for rx, reason in DENY_PATTERNS:
        if rx.search(cmd):
            return ("deny", "high", 0.95, reason)

    # 3) Require approval keywords (soft gate)
    if REQUIRE_APPROVAL:
        tokens = re.findall(r"[a-z0-9_./-]+", cmd.lower())
        if any(k in tokens for k in REQUIRE_APPROVAL):
            return ("review", "medium", 0.65, f"Requires approval: {', '.join(REQUIRE_APPROVAL)}")

    # 4) Default allow
    return ("allow", "low", 0.05, "No policy violations detected")
