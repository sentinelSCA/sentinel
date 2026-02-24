# Sentinel Command Authority (SCA) — v1.0 Blueprint
Status: 🔐 Scope Locked
Goal: Deterministic Self-Healing Governance Loop

---

## Core Identity

SCA is a deterministic security gateway that evaluates, signs, enforces,
and executes policy-controlled commands inside automation systems.

v1.0 Scope: Autonomous self-healing for Docker services.

---

# Architecture (Closed Loop)

Detect → Decide → Approve → Execute → Verify → Audit

---

## Components

### 1. probe-worker
- Polls service /health endpoints
- Pushes incidents to ops:incidents on failure
- Includes structured evidence

### 2. manager-worker
- Deduplicates incidents
- Applies cooldown
- Applies action budget
- Proposes restart_service when required

### 3. approver-bot
- Validates digest
- Requires human approval
- Pushes to ops:actions:approved

### 4. executor-worker
- Enforces allowlist
- Validates digest match
- Honors global freeze
- Executes docker compose restart

### 5. reaper-worker
- Recovers stuck inflight actions
- Quarantines excessive retries

---

## Redis Contracts

ops:incidents
ops:incidents:triaged
ops:actions:proposed
ops:actions:proposed:inflight
ops:actions:approved
ops:actions:approved:inflight
ops:actions:executed
ops:actions:rejected
ops:actions:quarantine

Global Freeze Key:
ops:freeze

---

## Allowed Actions (v1.0)

restart_service ONLY

No shell.
No arbitrary commands.
No file mutation.

---

## Definition of Done (Production Ready)

1. Stop sentinel-api manually
2. probe detects failure within 30 seconds
3. manager proposes exactly once (no spam)
4. approver validates digest
5. executor restarts service
6. probe verifies recovery
7. action logged in executed queue
8. no duplicate proposals
9. freeze halts execution instantly
10. reaper quarantines stuck actions

When this works 5 times consecutively without patching:
→ v1.0 ships.
