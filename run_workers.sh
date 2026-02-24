#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "[1/5] Loading env..."
set -a
source .env
set +a

mkdir -p logs

echo "[2/5] Starting Sentinel API on 127.0.0.1:8001..."
nohup ./venv/bin/uvicorn sentinel_api:app --host 127.0.0.1 --port 8001 > logs/api.log 2>&1 &

sleep 1

echo "[3/5] Starting Manager..."
nohup ./venv/bin/python worker_manager.py > logs/manager.log 2>&1 &

echo "[4/5] Starting Writer/Email/Twitter..."
nohup ./venv/bin/python worker_writer.py > logs/writer.log 2>&1 &
nohup ./venv/bin/python worker_email.py  > logs/email.log 2>&1 &
nohup ./venv/bin/python worker_twitter.py > logs/twitter.log 2>&1 &

echo "[5/5] DONE. Tail logs with:"
echo "  tail -f logs/api.log"
echo "  tail -f logs/manager.log"
echo "  tail -f logs/writer.log"
echo "  tail -f logs/email.log"
echo "  tail -f logs/twitter.log"
