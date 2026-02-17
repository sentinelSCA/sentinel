#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Load .env for TELEGRAM token + API URL + secrets
set -a
source .env
set +a

echo "✅ Starting Telegram Bot..."
./venv/bin/python bot.py
