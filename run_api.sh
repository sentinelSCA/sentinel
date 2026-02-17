#!/bin/bash
set -e
cd "$(dirname "$0")"
source venv/bin/activate

# API auth ON, signing OFF (for now)
export SENTINEL_API_KEY="sentinel-local-111111"
export SENTINEL_SIGNING_SECRET=""

exec uvicorn sentinel_api:app --host 127.0.0.1 --port 8001
