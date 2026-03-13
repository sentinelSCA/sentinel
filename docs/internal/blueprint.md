# Sentinel Compliance Agent (SCA) — Blueprint v1 (LOCKED)

## Definition
SCA is a deterministic security gateway that evaluates, signs, and enforces policies on commands before execution.
It protects automation systems, bots, and AI agents.

## What SCA ships in v1 (the capped scope)
### A) Security Gateway (DONE)
- `/analyze` accepts a command request and returns: allow/deny/review + risk + reason
- Requires API key + HMAC signature headers (when enabled)
- Replay protection (redis/sqlite) and timestamp window enforcement
- Audit chain logging (append-only + head)

### B) Governed Ops (DONE)
- Incidents → Manager triage → Proposal → Human approval → Executor → Executed log
- Digest match enforcement on approvals (when enabled)
- Cooldown + budget + global freeze kill-switch
- Reaper recovers stale inflight actions

### C) Self-detecting autonomy (FINAL ADD)
- A probe-worker periodically checks service health and pushes incidents automatically.
- No extra autonomy beyond incident generation; all actions still require approval.

## Explicit non-goals for v1 (to prevent diversion)
- No “AI agent marketplace integration” in v1
- No new worker types beyond probe-worker
- No new policy versions beyond v2
- No new UIs beyond basic monitoring tools (optional)

## “Done” criteria (close the loop)
v1 is production-ready when:
1) probe-worker generates incidents for unhealthy services
2) manager proposes exactly one valid action (dedupe + cooldown + budget enforced)
3) approver approves with digest match
4) executor executes idempotently OR blocks when frozen
5) reaper recovers stale inflight and quarantines after max retries
6) logs/audit show the full chain for an e2e test
