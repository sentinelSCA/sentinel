# Sentinel Protocol Specification

Sentinel is a deterministic execution firewall for AI agents.

This protocol defines how AI agents authenticate, request actions,
and how Sentinel evaluates, approves, executes, and records those actions.

---

# Architecture Flow

AI Agent
↓
Agent Identity (Ed25519)
↓
Capability Tokens
↓
Schema Validation
↓
Behavior Limits
↓
Policy Engine
↓
Deterministic Action Hash
↓
Execution Worker
↓
AI Action Report
↓
Deterministic Execution Ledger
↓
Hash-Chained Audit Log
↓
Live Action Timeline
↓
Action Replay & Forensics

---

# Agent Identity

Agents authenticate using Ed25519 public key cryptography.

Example agent registration:

{
 "agent_id": "deploy-bot-7",
 "public_key": "ed25519:f83a912aa..."
}

---

# Action Request

Agents send structured signed requests.

Example:

{
 "agent_id": "deploy-bot-7",
 "timestamp": "2026-03-15T18:41:00Z",
 "capability": "deploy:staging",
 "action": {
   "type": "deploy",
   "service": "api-service",
   "version": "1.3"
 }
}

---

# Policy Decision

Sentinel evaluates requests and returns:

ALLOW  
REVIEW  
DENY  

Example response:

{
 "decision": "review",
 "risk_score": 0.82,
 "policy_version": "4.2"
}

---

# AI Action Report (Canonical Event Format)

Every evaluated agent action produces a structured **AI Action Report**.

This report is the canonical record used for:

- audit logging
- timeline monitoring
- forensic replay
- ledger integrity

Example:

AI ACTION REPORT
----------------
Event ID: evt_9c41ab72

Agent: deploy-bot-7  
Identity: ed25519:f83a...  

Environment: production  
Capability: deploy:staging  

Action: deploy(api-service v1.3)

Decision: ALLOWED  
Approved By: system-policy  

Policy Version: 4.2  
Risk Score: 0.18  

Timestamp: 2026-03-15T18:41:00Z  

Execution Hash: 78ac21...  
Previous Hash: 17fa09...

---

# Deterministic Execution Ledger

Action reports are chained together using cryptographic hashes.

hash_n = SHA256(hash_n-1 + action_report)

This produces a **tamper-evident ledger of AI system activity**.

---

# Live Action Timeline

Sentinel exposes a real-time timeline of agent activity for operators.

This allows teams to observe:

- actions being evaluated
- approvals and denials
- execution results
- system anomalies

---

# Action Replay & Forensics

Security teams can replay historical action reports to investigate incidents.

This enables:

- forensic reconstruction of agent behavior
- validation of policy enforcement
- incident response analysis
