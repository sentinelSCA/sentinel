import os
import time
import json
import requests
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

TRIAGED_Q = os.getenv("OPS_INCIDENTS_TRIAGED_Q", "ops:incidents:triaged")

r = redis.from_url(REDIS_URL, decode_responses=True)

def send_telegram(msg: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": msg}
    requests.post(url, json=payload, timeout=10)

def run():
    print("Telegram notifier worker started...", flush=True)

    while True:
        raw = r.blpop(TRIAGED_Q, timeout=5)
        if not raw:
            continue

        _, payload = raw
        try:
            data = json.loads(payload)
        except Exception:
            continue

        incident = data.get("incident", {})
        msg = f"""🚨 Sentinel Alert

Service: {incident.get("service")}
Kind: {incident.get("kind")}
Severity: {data.get("severity")}
"""

        try:
            send_telegram(msg)
            print("Telegram alert sent", flush=True)
        except Exception as e:
            print("Telegram error:", e, flush=True)

if __name__ == "__main__":
    run()
