#!/usr/bin/env bash
set -a
source .env
set +a
source venv/bin/activate

HOST="127.0.0.1"
PORT="${PORT:-8000}"

# If port is busy, use 8001
if ss -ltn | grep -q ":$PORT "; then
  echo "Port $PORT is busy, switching to 8001"
  PORT=8001
fi

exec uvicorn sentinel_api:app --host "$HOST" --port "$PORT"
