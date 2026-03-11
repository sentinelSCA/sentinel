# Sentinel

Sentinel is an AI agent security gateway that sits between autonomous agents and real infrastructure.

It verifies agent identity, validates signed action requests, applies policy decisions, records tamper-evident audit logs, and routes approved actions through a controlled execution layer.

---

# What Sentinel Does

Sentinel provides:

• Ed25519 agent identity and signed requests  
• Timestamp and replay protection  
• Strict command validation  
• Policy-based allow / review / deny decisions  
• Reputation-aware decision support  
• Human approval workflow for sensitive actions  
• Adapter-based executor control  
• Append-only tamper-evident audit chain  
• Telemetry and operator dashboard  
• Python SDK for agent integration

---

# Architecture

AI Agent  
   │  
   │ signed request  
   ▼  
Sentinel API  
   │  
   ├─ identity verification  
   ├─ replay protection  
   ├─ command validation  
   ├─ policy engine  
   │  
   ▼  
Decision  
   │  
   ├─ allow  → executor  
   ├─ review → human approval  
   └─ deny  
   │  
   ▼  
Audit chain + telemetry + dashboard

---

# Core Components

sentinel_api.py  
Main API entrypoint and decision pipeline.

sentinel_api_with_dashboard.py  
Homepage and operator dashboard.

agent_identity.py  
Agent registration and Ed25519 identity verification.

sentinel_core/risk_engine.py  
Risk scoring and decision evaluation.

sentinel_core/action_digest.py  
Canonical digest generation for actions.

sentinel_core/audit.py  
Append-only tamper-evident audit chain.

executor_worker.py  
Controlled execution worker with digest verification.

sdk/sentinel_agent/  
Python SDK for agent integration.

---

# Request Protocol

Headers

X-Signature  
X-Timestamp-Unix  

Body

{
  "agent_id": "agent_xxx",
  "command": "{\"type\":\"read_url\",\"target\":\"https://example.com/health\",\"method\":\"GET\"}",
  "timestamp": "1773214000"
}

Sentinel verifies:

• agent public key  
• Ed25519 signature  
• timestamp freshness  
• replay protection  
• command schema  
• policy outcome

---

# Python SDK Example

from sentinel_agent import SentinelAgentClient

client = SentinelAgentClient(
    base_url="https://sentinelsca.com",
    agent_id="agent_xxx",
    priv_b64="BASE64_PRIVATE_KEY"
)

resp = client.analyze({
    "type": "read_url",
    "target": "https://example.com/health",
    "method": "GET"
})

print(resp["decision"])

---

# Dashboard

Sentinel includes:

/ — homepage  
/dashboard — operator dashboard  
/telemetry — telemetry endpoint

The dashboard displays:

• queue state  
• telemetry panel  
• recent activity  
• agent inventory  
• approval workflow context

---

# Current Status

Sentinel currently includes:

• signed request verification  
• Ed25519 agent registration  
• replay protection  
• strict command validation  
• policy engine and reputation logic  
• digest verification before execution  
• hash-chained audit log  
• operator dashboard and telemetry  
• installable Python SDK

---

# Repository Layout

sentinel/
├── agent_identity.py
├── executor_worker.py
├── sentinel_api.py
├── sentinel_api_with_dashboard.py
├── sentinel_core/
├── sentinel_rules/
├── templates/
├── static/
├── sdk/
├── docs/
└── scripts/

---

# Design Goal

Sentinel is intentionally simple:

verify identity  
validate actions  
enforce policy  
control execution  
record evidence

---

# License

Add your project license here.
