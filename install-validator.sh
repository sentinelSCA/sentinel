#!/usr/bin/env bash
set -e

echo "🔒 Sentinel Validator Edition Installer"

echo "1️⃣ Checking Docker..."
if ! command -v docker &> /dev/null; then
  echo "Docker not found. Installing..."
  sudo apt update
  sudo apt install -y docker.io docker-compose
  sudo systemctl enable docker
  sudo systemctl start docker
fi

echo "2️⃣ Generating .env if missing..."
if [ ! -f .env ]; then
  cp .env.example .env || touch .env
fi

grep -q '^API_KEY=' .env || echo "API_KEY=$(openssl rand -hex 32)" >> .env
grep -q '^SENTINEL_SIGNING_SECRET=' .env || echo "SENTINEL_SIGNING_SECRET=$(openssl rand -hex 32)" >> .env
grep -q '^REDIS_PASSWORD=' .env || echo "REDIS_PASSWORD=$(openssl rand -hex 32)" >> .env
grep -q '^STRICT_MODE=' .env || echo "STRICT_MODE=true" >> .env
grep -q '^COMPOSE_FILE=' .env || echo "COMPOSE_FILE=/app/docker-compose.validator.yml" >> .env
grep -q '^COMPOSE_PROJECT_DIR=' .env || echo "COMPOSE_PROJECT_DIR=/app" >> .env
grep -q '^COMPOSE_ENV_FILE=' .env || echo "COMPOSE_ENV_FILE=/app/.env" >> .env

echo "3️⃣ Starting Validator Edition..."
docker compose -f docker-compose.validator.yml up -d --build

echo "4️⃣ Health Check..."
sleep 5
curl -s http://127.0.0.1:8001/health || true

echo ""
echo "✅ Installation complete."
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8001/dashboard"
echo ""
echo "IMPORTANT: Secure your dashboard behind a reverse proxy in production."
