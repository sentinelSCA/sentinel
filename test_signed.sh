#!/usr/bin/env bash
set -euo pipefail
cd ~/sentinel

set -a; source .env; set +a

TS_UNIX=$(date +%s)
BODY=$(printf '{"agent_id":"local","command":"echo hello","timestamp":"%s"}' "$TS_UNIX")

SIG=$(
  ./venv/bin/python - <<'PY'
import os, json, hmac, hashlib, time
secret=os.environ["SENTINEL_SIGNING_SECRET"]
ts=str(int(time.time()))
payload={"agent_id":"local","command":"echo hello","timestamp":ts,"ts_unix":ts}
msg=json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
print(hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest())
PY
)

curl -s -X POST "http://127.0.0.1:8001/analyze" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SENTINEL_API_KEY" \
  -H "X-Timestamp-Unix: $TS_UNIX" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
echo
