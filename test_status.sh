#!/usr/bin/env bash
set -euo pipefail

cd ~/sentinel
set -a; source .env; set +a

TS=$(date +%s)

SIGNED=$(python3 - <<PY
import json
print(json.dumps({"agent_id":"local","ts_unix":str(${TS})}, sort_keys=True, separators=(",",":")))
PY
)

SIG=$(printf '%s' "$SIGNED" | openssl dgst -sha256 -hmac "$SENTINEL_SIGNING_SECRET" | awk '{print $2}')

curl -s "http://127.0.0.1:8001/api/v1/status/local" \
  -H "X-API-Key: $SENTINEL_API_KEY" \
  -H "X-Timestamp-Unix: $TS" \
  -H "X-Signature: $SIG"

echo
