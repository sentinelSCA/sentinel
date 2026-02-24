# Sentinel SCA

Sentinel SCA is a Deterministic Enforcement Layer for Autonomous Agents.

It acts as a cryptographic policy gateway between AI agents and execution environments.

Its purpose is simple:

Autonomous systems must not execute without enforceable, auditable, deterministic control.

---

# The Problem

AI agents are increasingly capable of:

- Executing shell commands
- Managing infrastructure
- Sending emails
- Posting to social platforms
- Interacting with external APIs
- Orchestrating other agents

Most systems today rely on:

- Prompt engineering
- Soft guardrails
- Basic API keys
- Application-level checks

These are not enforcement mechanisms.

They are suggestions.

Once agents gain execution capability, the absence of deterministic enforcement becomes a systemic risk.

Sentinel exists to solve that.

---

# Core Principle

LLMs generate.
Sentinel enforces.

Policy must be:

- Deterministic
- Cryptographically verifiable
- Auditable
- Replay-resistant
- Tamper-evident

Security cannot depend on model behavior.

---

# Core Architecture

Sentinel SCA consists of:

1. API Gateway (FastAPI)
2. HMAC request signing
3. Ed25519 agent identity
4. Deterministic policy engine
5. Audit-chain hashing (WORM-style integrity)
6. Resource-limited sandbox execution
7. Reputation engine
8. Rate limiting engine
9. Multi-agent orchestration system

---

# Enforcement Flow

Agent → Signed Request → Sentinel → Policy Engine → Execution Sandbox → Audit Chain → Reputation Update

Step-by-step:

1. Agent signs request (HMAC + optional Ed25519)
2. Sentinel validates:
   - API key
   - Timestamp window
   - Signature integrity
   - Nonce replay protection
3. Deterministic policy evaluation
4. If allowed:
   - Command executed inside sandbox
   - Execution recorded
   - Audit chain updated
   - Reputation adjusted
5. If denied:
   - Decision logged
   - Audit chain updated

Every decision is traceable.

---

# Threat Model

Sentinel is designed to mitigate:

- Prompt injection
- Replay attacks
- Agent impersonation
- Command escalation
- Audit tampering
- Resource exhaustion
- Autonomous abuse loops
- Signature forgery
- Timestamp manipulation

Sentinel assumes agents can be compromised.
Enforcement must not rely on trust.

---

# Security Model

Sentinel enforces:

- API key validation
- HMAC request signature verification
- Optional Ed25519 agent identity
- Timestamp window protection
- Nonce replay prevention
- Immutable audit chain
- Resource-limited sandbox execution
- Command allowlist filtering
- Deterministic policy evaluation

---

# Audit Chain

Each request produces:

Hash = SHA256(prev_hash + entry_json)

Optional HMAC signature of entry hash.

This creates tamper detection across the entire request history.

Audit head is available via:

GET /audit/head

The audit chain is append-only.

---

# Reputation Engine

Each agent accumulates behavioral reputation.

Policy can incorporate:

- Rate violations
- Denied actions
- Escalation attempts
- Signature anomalies
- Execution failures

Reputation becomes a programmable enforcement primitive.

---

# Multi-Agent System

Sentinel supports structured multi-agent workflows:

- Manager Agent (incident classification & decision logic)
- Maintenance Agent (infrastructure monitoring)
- Approver Agent (policy approval gate)
- Executor Agent (sandboxed execution)
- Writer Agent (LLM content generation)
- Verifier Agent (content grounding validation)
- Publish Agents (Twitter / Email)

All execution passes through Sentinel.

No direct execution is trusted.

---

# Deterministic vs LLM Guardrails

LLM guardrails are probabilistic.

Sentinel enforcement is deterministic.

LLMs may recommend.
Sentinel decides.

This separation is intentional.

---

# Roadmap

Phase 1:
- Secure command gateway
- Signed API
- Audit chain
- Telegram interface

Phase 2:
- Multi-agent orchestration
- Local LLM integration (Ollama)
- Content verification system

Phase 3:
- Agent marketplace integration
- MCP compatibility
- gRPC fleet communication
- WebSocket audit streaming

Phase 4:
- Distributed enforcement nodes
- Delegation model
- Validator economy
- Cross-agent reputation scoring

---

# Vision

Sentinel is not just SCA.

It is an enforcement protocol for the autonomous internet.

As AI agents become infrastructure actors, they require:

- Deterministic control
- Cryptographic identity
- Auditable decision systems
- Resource-bound execution
- Reputation-based trust

Sentinel aims to become the enforcement layer between autonomy and execution.
