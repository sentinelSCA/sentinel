# Sentinel Protocol – Current System State

## Architecture

Sentinel is an agent governance + operations control plane built with:

- FastAPI (sentinel-api)
- Redis (queue + state)
- Telegram bot (sentinel-bot)
- Maintenance Worker (observer / incident proposer)
- Approver Bot (human-in-the-loop approval)
- Executor Worker (controlled action executor)

All services run via Docker Compose.

---

## Running Services

- sentinel-api
- redis
- sentinel-bot
- maintenance-worker
- approver-bot
- executor-worker

All containers are healthy and communicating via internal Docker network.

---

## Governance Flow (Working)

1. Maintenance Worker monitors `/health`
2. If unhealthy → pushes incident to `ops:incidents`
3. Proposes action → `ops:actions:proposed`
4. Approver Bot:
   - Moves approved actions → `ops:actions:approved`
   - Stores pending actions under `ops:pending:*`
5. Executor Worker:
   - Consumes `ops:actions:approved`
   - Validates allowed types
   - Executes controlled docker compose restart
   - Logs result to `ops:actions:executed`

Rejected actions go to:
- `ops:actions:rejected`

---

## Allowed Executor Actions

Currently supported:
- restart_service (restricted to whitelisted services)

Blocked example:
- rm_rf
- arbitrary shell execution

---

## Security State

- API key enforced
- HMAC signing available
- Ed25519 support scaffolded
- Replay protection active
- Reputation tracking active

---

## Redis Queues

ops:incidents
ops:actions:proposed
ops:actions:approved
ops:actions:executed
ops:actions:rejected
ops:pending:<action_id>

---

## Known Decisions

- System is stable
- Telegram approval loop working
- Executor safeguards working
- Docker restart integration confirmed

---

## Next Expansion Goals

- Strong Ed25519 enforcement
- Service-level allowlist policy
- Observability (Prometheus / metrics)
- Executor isolation hardening
- Rate limiting ops actions
- Policy-based auto-approval rules

---

## Vision

Sentinel becomes:
A self-governing agent operations protocol  
with human oversight and controlled autonomy.

---

End of state.
