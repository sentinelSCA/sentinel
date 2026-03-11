#!/usr/bin/env bash
set -euo pipefail

cd ~/sentinel

API_KEY="$(awk -F= '/^API_KEY=/{print $2}' .env | tr -d "\r\n")"
if [[ -z "${API_KEY}" ]]; then
  echo "ERROR: API_KEY is empty. Check .env"
  exit 1
fi

AGENT_ID="$(awk -F= '/^AGENT_ID=/{print $2}' .env | tr -d "\r\n")"

CMD_JSON="${1:-}"
if [[ -z "${CMD_JSON}" ]]; then
  echo 'Usage: ./scripts/send_cmd.sh '"'"'{"type":"restart_service","target":"sentinel-api","reason":"test"}'"'"''
  exit 1
fi

# get server time (avoid timestamp window errors)
TS_UNIX="$(docker compose -f docker-compose.validator.yml exec -T sentinel-api sh -lc 'date -u +%s' | tr -d '\r')"
TS_ISO="$(docker compose -f docker-compose.validator.yml exec -T sentinel-api sh -lc 'date -u +%Y-%m-%dT%H:%M:%SZ' | tr -d '\r')"

# payload the server signs
SIGNED_PAYLOAD="$(python3 - <<PY
import json
payload={
  "agent_id":"$AGENT_ID",
  "command": """$CMD_JSON""",
  "timestamp": """$TS_ISO""",
  "ts_unix": """$TS_UNIX""",
}
print(json.dumps(payload, separators=(",",":")))
PY
)"

# compute signature using the container's sentinel_api._sign_payload
SIG="$(docker compose -f docker-compose.validator.yml exec -T \
  -e SIGNED_PAYLOAD="$SIGNED_PAYLOAD" \
  sentinel-api python - <<'PY'
import os, json, sentinel_api
payload=json.loads(os.environ["SIGNED_PAYLOAD"])
print(sentinel_api._sign_payload(payload))
PY
)"

# request body (command must be a string)
BODY="$(python3 - <<PY
import json
body={
  "agent_id":"$AGENT_ID",
  "timestamp":"$TS_ISO",
  "command": """$CMD_JSON""",
}
print(json.dumps(body))
PY
)"

echo
echo "---- SENDING ----"
echo "$CMD_JSON"

curl -sS -X POST http://127.0.0.1:8001/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-TIMESTAMP-UNIX: $TS_UNIX" \
  -H "X-SIGNATURE: $SIG" \
  -d "$BODY" | python3 -m json.tool
