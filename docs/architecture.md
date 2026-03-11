# Sentinel Security Model

Sentinel enforces deterministic authorization for agent actions.

## Identity

Agents are registered with Ed25519 public keys.

Each action request must include:

• agent_id
• timestamp
• signature

The signature is verified before processing.

---

## Replay Protection

Sentinel rejects requests that:

• fall outside the timestamp window
• reuse previously seen signatures

This prevents replay attacks.

---

## Policy Enforcement

Actions are evaluated by a deterministic policy engine.

Decisions:

allow  
review  
deny

Only allow decisions reach the execution layer.

---

## Controlled Execution

Execution occurs through adapter modules.

Adapters restrict the scope of allowed infrastructure actions.

Example adapters:

restart_service  
read_url  
scale_service

Direct shell execution is not permitted.

---

## Audit Integrity

Every action produces an audit log entry.

Audit logs are append-only and chained to detect tampering.
