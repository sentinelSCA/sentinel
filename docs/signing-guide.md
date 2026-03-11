# Sentinel SCA — Signing Guide (Validator Shield Edition)

This guide shows how to call `/analyze` in **strict signed mode**.

In strict mode, Sentinel requires:
- `X-API-KEY`
- `X-TIMESTAMP-UNIX`
- `X-SIGNATURE`

Sentinel signs a canonical JSON payload using `SENTINEL_SIGNING_SECRET`.

---

## Required `.env` values

On the Sentinel server (VPS), these must exist:

- `API_KEY=...` (your client uses this)
- `SENTINEL_SIGNING_SECRET=...` (server signing secret; do NOT share publicly)
- `SENTINEL_STRICT_MODE=1` or `STRICT_MODE=true` (depending on your env naming)

**Important:**
- `API_KEY` is the value you send in `X-API-KEY`.
- `SENTINEL_SIGNING_SECRET` is the HMAC secret used to verify `X-SIGNATURE`.

---

## Endpoint

Local:
- `http://127.0.0.1:8001/analyze`

Behind Caddy / domain:
- `https://sentinelsca.com/analyze` (if reverse-proxied)

---

## The request body format

The API expects:

```json
{
  "agent_id": "string",
  "timestamp": "2026-02-28T00:00:00Z",
  "command": "{\"type\":\"restart_service\",\"target\":\"sentinel-api\",\"reason\":\"...\"}"
}
