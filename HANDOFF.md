# Sentinel project handoff (for new ChatGPT thread)

## Goal
We are building Sentinel governance + ops automation:
maintenance-worker -> proposes ops actions
approver-bot -> sends Telegram approve/reject buttons
executor-worker -> executes only allowlisted actions (restart_service etc)
All connected via Redis queues.

## Current services in docker-compose.yml
- sentinel-api (FastAPI) on 8001
- redis
- sentinel-bot (Telegram bot)
- maintenance-worker
- approver-bot
- executor-worker

## Redis queues/keys
- ops:incidents
- ops:actions:proposed
- ops:actions:approved
- ops:actions:rejected
- ops:actions:executed
- ops:pending:<action_id>   (approver-bot stores pending actions here)

## Known previous issues solved
- curl/register 404 fixed by restarting correct container build
- /analyze requires signature headers when REQUIRE_AGENT_SIG=1 and signing secret set
- compose errors were due to YAML indentation / duplicate keys

## Current problem to solve (today)
(Write what’s broken right now, e.g. approver flow, pending keys, bot endpoint, etc.)

## Commands that confirm status
docker compose ps
docker compose logs --tail=120 approver-bot
docker compose logs --tail=120 executor-worker
docker compose exec -T redis redis-cli --scan --pattern 'ops:*' | sort
