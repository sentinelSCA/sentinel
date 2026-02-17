#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Load .env into environment (API key + signing secret + urls)
set -a
source .env
set +a

echo "✅ Starting Sentinel API on http://127.0.0.1:8000"
./venv/bin/python -m uvicorn sentinel_api:app --host 127.0.0.1 --port 8000
