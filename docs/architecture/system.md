UNTRUSTED ZONE
                (Autonomous AI Agents / LLMs)

+--------------------------------------------------+
|                    AI AGENT                      |
|     LLM / Automation / External AI System        |
+--------------------------+-----------------------+
                           |
                           | Signed action request
                           | (Ed25519 + timestamp)
                           v

===================== SENTINEL SECURITY BOUNDARY =====================

+--------------------------------------------------+
|                  Sentinel API                    |
|--------------------------------------------------|
| • Agent identity verification                    |
| • Signature validation                           |
| • Replay protection                              |
| • Command schema validation                      |
| • Policy evaluation                              |
| • Reputation gating                              |
+---------------------+----------------------------+
                      |
                      v

+--------------------------------------------------+
|                Decision Engine                   |
|--------------------------------------------------|
| allow      → send directly to execution queue    |
| review     → require human approval              |
| deny       → block + audit                       |
+-----------+------------------+-------------------+
            |                  |
            | allow            | review
            v                  v

+-------------------------+    +----------------------------+
|    Execution Queue      |    |      Human Approval        |
|   (Redis / Action ID)   |    |      Operator Dashboard    |
+-----------+-------------+    +-------------+--------------+
            |                                |
            | approved action                |
            +---------------+----------------+
                            v

+--------------------------------------------------+
|                Executor Worker                   |
|--------------------------------------------------|
| • Recomputes action digest                       |
| • Verifies integrity                             |
| • Executes only approved actions                 |
+-------------------------+------------------------+
                          |
                          v

+--------------------------------------------------+
|                Safe Adapters                     |
|--------------------------------------------------|
| restart_service                                  |
| read_url                                         |
| scale_service                                    |
| clear_cache                                      |
+-------------------------+------------------------+
                          |
                          v

+--------------------------------------------------+
|                Infrastructure                    |
|--------------------------------------------------|
| Docker / APIs / Kubernetes / External Services   |
+--------------------------------------------------+

Telemetry, audit logs, and queue metrics span all stages.


Security Boundary

Sentinel enforces a strict execution boundary between autonomous agents and infrastructure.

AI agents never interact with infrastructure directly.

All actions must pass through Sentinel’s verification and policy enforcement layers.

This ensures:
	•	authenticated agent identity
	•	signed requests
	•	replay protection
	•	policy-driven authorization
	•	human approval for sensitive operations
	•	deterministic execution

⸻

Execution Flow
	1.	An AI agent sends a signed action request to Sentinel.
	2.	Sentinel verifies:
	•	agent identity
	•	request signature
	•	timestamp freshness
	•	replay protection
	3.	The policy engine evaluates the command and produces a decision:
	•	allow
	•	review
	•	deny
	4.	If allow, the action is placed into the execution queue.
	5.	If review, it appears in the operator dashboard for human approval.
	6.	The executor worker verifies the action digest and executes the action through a controlled adapter.
	7.	Execution results are recorded in telemetry and audit logs.

⸻

Core Security Guarantees

Sentinel provides several guarantees designed for AI-driven infrastructure automation.

Agent Identity

Agents authenticate using Ed25519 public key identity.

Signed Requests

All action requests are cryptographically signed.

Replay Protection

Requests include timestamps and replay detection.

Policy Enforcement

Actions are evaluated by a deterministic policy engine.

Human Approval

Sensitive actions require manual approval.

Controlled Execution

Actions are executed only by verified executor workers.

Audit Visibility

Every decision and execution event is recorded for telemetry and auditing.

⸻

Sentinel’s Role

Sentinel functions as a firewall for AI agents.

Instead of allowing autonomous agents to directly control infrastructure, Sentinel ensures that every action is verified, evaluated, and executed under strict security control.
