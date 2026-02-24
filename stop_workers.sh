#!/usr/bin/env bash
set -e

echo "Stopping workers + api..."
pkill -f "uvicorn sentinel_api:app" || true
pkill -f "worker_manager.py" || true
pkill -f "worker_writer.py" || true
pkill -f "worker_email.py" || true
pkill -f "worker_twitter.py" || true
echo "Done."
