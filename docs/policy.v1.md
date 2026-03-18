# Sentinel Decision Policy (v1)

## Overview
Sentinel evaluates AI agent actions and determines whether to:
- Allow (auto-execute)
- Require human review
- Deny

This ensures safe, scalable automation.

---

## Decision Flow

Action → Risk Classification → Decision

### Low Risk → Auto Execute
These actions are considered safe and execute immediately.

- read_url
- clear_cache

Behavior:
- Automatically approved
- Automatically executed
- No human involvement

---

### Medium / High Risk → Human Review

These actions require operator approval before execution.

- restart_service
- scale_service
- rotate_keys

Behavior:
- Placed in "Needs Review" queue
- Requires manual approve/reject
- Executed only after approval

---

### Unknown / Unsupported → Deny

Any unrecognized action is rejected.

Behavior:
- Immediately rejected
- No execution

---

## Execution Model

- Approved actions → executed
- Rejected actions → never executed
- Auto-approved actions → executed immediately

---

## System Guarantees

- No execution without approval (explicit or automatic)
- Full audit trail (approved / rejected / executed)
- Deterministic action hashing
- Redis-backed queue integrity

---

## Future Enhancements

- Reputation-based decisions
- Environment-aware policies (dev vs prod)
- Time-based restrictions
- Multi-signature approvals

