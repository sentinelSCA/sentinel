#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Load .env (export variables)
set -a
source .env
set +a

CMD="${1:-ls}"
AGENT_ID="${2:-a}"
TS="$(date +%s)"

SIG="$(./venv/bin/python - <<PY
import os, hmac, hashlib, json
secret = os.environ["SENTINEL_SIGNING_SECRET"]
payload = {
  "agent_id": "$AGENT_ID",
  "command": "$CMD",
  "timestamp": "123",
  "ts_unix": str($TS),
}
msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
print(hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest())
PY
)"

curl -s -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SENTINEL_API_KEY" \
  -H "X-Timestamp-Unix: $TS" \
  -H "X-Signature: $SIG" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"command\":\"$CMD\",\"timestamp\":\"123\"}"

echo
