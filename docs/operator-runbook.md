# Sentinel Validator Shield — Operator Runbook

This is the day-to-day operating guide for a validator operator using Sentinel.

---

## Services

Validator Shield stack (compose):
- sentinel-api
- redis
- manager-worker
- probe-worker
- reaper-worker
- executor-worker
- approver-bot
- (optional) portainer / dozzle

---

## Health checks

Local (on VPS):
- `curl -sS http://127.0.0.1:8001/health`

Expected:
- `"status":"ok"`
- `"strict_mode": true`
- replay backend usually `redis`

Dashboard:
- `http://127.0.0.1:8001/dashboard`
- or `https://<your-domain>/dashboard` behind Caddy (Basic Auth protected)

---

## Logs

API logs:
- `docker compose -f docker-compose.validator.yml logs -f --tail=200 sentinel-api`

Worker logs:
- `docker compose -f docker-compose.validator.yml logs -f --tail=200 manager-worker`
- `docker compose -f docker-compose.validator.yml logs -f --tail=200 probe-worker`
- `docker compose -f docker-compose.validator.yml logs -f --tail=200 executor-worker`
- `docker compose -f docker-compose.validator.yml logs -f --tail=200 approver-bot`

---

## Restart / stop

Restart stack:
- `docker compose -f docker-compose.validator.yml restart`

Restart one service:
- `docker compose -f docker-compose.validator.yml restart sentinel-api`

Stop:
- `docker compose -f docker-compose.validator.yml down`

---

## Policy behavior (Validator Edition)

The validator hard-lock is designed to:
- allow only safe actions automatically
- push risky actions to `review` for human approval

Expected:
- restart `sentinel-api` => allow
- restart `redis` => review (requires approval)

If you see anything else, treat as misconfiguration.

---

## Approval flow (human-in-the-loop)

Queues (Redis):
- `ops:actions:proposed`
- `ops:actions:approved`
- `ops:actions:executed`
- `ops:actions:rejected`

Approver bot:
- watches proposed queue
- checks digest + allowed types/targets
- requires human approval unless auto-approve enabled

---

## Test commands

From repo root on VPS:

Allow test:
- `./scripts/send_cmd.sh '{"type":"restart_service","target":"sentinel-api","reason":"operator test - allow"}'`

Review test:
- `./scripts/send_cmd.sh '{"type":"restart_service","target":"redis","reason":"operator test - review"}'`

---

## Common incidents

### 1) "Invalid API key"
- Confirm `.env` contains `API_KEY=...`
- Confirm you are sending header `X-API-KEY` with the same value

### 2) "Missing signature headers" / "Bad signature"
- Confirm `.env` contains `SENTINEL_SIGNING_SECRET=...`
- Confirm strict mode is enabled
- Use `scripts/send_cmd.sh` (it signs using the container code path)

### 3) "Timestamp outside allowed window"
- NTP drift or client time mismatch
- `scripts/send_cmd.sh` uses server time automatically

### 4) Redis AUTH error
- Redis password mismatch between Redis container and app env
- Confirm `.env` `REDIS_PASSWORD=...`
- Confirm redis service uses that password (if enabled)

---

## Backup

Recommended:
- daily Redis backup
- daily policy + env backup (encrypted/offsite)

If using a backup script:
- store backups under `~/sentinel_backups/`
- ensure backups are not publicly accessible

---

## Security reminders

- Keep port 8001 bound to localhost only (reverse proxy handles public traffic).
- Protect `/dashboard` with Basic Auth (Caddy).
- Keep `.env` private.
- Rotate API key + signing secret if you suspect leak.
