import os
import json
import time
import uuid
import hmac
import hashlib
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

from queue_redis import qpop, qpush

load_dotenv(".env")

# ----------------------------
# Config
# ----------------------------
SENTINEL_URL = os.getenv("SENTINEL_URL", "http://sentinel-api:8001/analyze").strip()
API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()
SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "").strip()

IN_QUEUE = os.getenv("EMAIL_GEN_QUEUE", "tasks:generate:email").strip()
VERIFY_QUEUE = os.getenv("VERIFY_QUEUE", "tasks:verify").strip()

AGENT_ID = os.getenv("EMAIL_AGENT_ID", "worker:email").strip()
POLL_SEC = float(os.getenv("EMAIL_POLL_SEC", "1").strip() or "1")

if not API_KEY:
    raise RuntimeError("Missing SENTINEL_API_KEY in .env")
if not SIGNING_SECRET:
    raise RuntimeError("Missing SENTINEL_SIGNING_SECRET in .env")

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _sentinel_headers(agent_id: str, command: str, timestamp_iso: str, ts_unix: str):
    # must match sentinel_api.py expectation:
    # body signs {"agent_id","command","timestamp","ts_unix"}
    hmac_body = json.dumps(
        {"agent_id": agent_id, "command": command, "timestamp": timestamp_iso, "ts_unix": ts_unix},
        sort_keys=True,
        separators=(",", ":"),
    )
    x_sig = hmac.new(SIGNING_SECRET.encode("utf-8"), hmac_body.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Timestamp-Unix": ts_unix,
        "X-Signature": x_sig,
    }

def call_sentinel(command: str):
    ts_iso = _now_iso()
    ts_unix = str(int(time.time()))

    payload = {
        "agent_id": AGENT_ID,
        "command": command,
        "timestamp": ts_iso,
        "reputation": 0.0,
    }

    headers = _sentinel_headers(AGENT_ID, command, ts_iso, ts_unix)
    r = requests.post(SENTINEL_URL, json=payload, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()

def generate_email_body(job: dict) -> str:
    subject = (job.get("subject") or "No subject").strip()
    topic = (job.get("topic") or "").strip()
    tone = (job.get("tone") or "professional").strip()

    lines = []
    lines.append(f"(tone={tone})")
    if topic:
        lines.append(f"Topic: {topic}")
    lines.append("")
    lines.append("Key points (draft):")
    lines.append("- Policy enforced via Sentinel SCA")
    lines.append("- Signed + audited")
    lines.append("- Pending verification (verifier-worker)")
    lines.append("")
    lines.append(f"Generated at: {_now_iso()}")
    lines.append(f"Agent: {AGENT_ID}")
    return "\n".join(lines)

def run_loop():
    print("Email worker started (Redis queue mode).", flush=True)
    print("IN_QUEUE =", IN_QUEUE, flush=True)
    print("VERIFY_QUEUE =", VERIFY_QUEUE, flush=True)
    print("SENTINEL_URL =", SENTINEL_URL, flush=True)
    print("AGENT_ID =", AGENT_ID, flush=True)

    while True:
        job = qpop(IN_QUEUE, timeout=5)
        if not job:
            time.sleep(POLL_SEC)
            continue

        try:
            to_addr = (job.get("to") or "").strip()
            subject = (job.get("subject") or "No subject").strip()
            topic = (job.get("topic") or "").strip()
            tone = (job.get("tone") or "professional").strip()
            job_id = (job.get("id") or f"email_{uuid.uuid4()}").strip()

            # sentinel gate
            cmd = f"write email subject={subject} topic={topic} tone={tone}"
            decision = call_sentinel(cmd)
            if decision.get("decision") != "allow":
                print("Blocked by Sentinel:", decision.get("reason"), flush=True)
                continue

            body = generate_email_body(job)

            # Send to verifier as TEXT (not file path)
            verify_payload = {
                "id": job_id,
                "kind": "email",
                "to": to_addr,
                "subject": subject,
                "body": body,
                "created_at": _now_iso(),
            }
            qpush(VERIFY_QUEUE, verify_payload)

            print("Enqueued verify →", job_id, flush=True)

        except Exception as e:
            print("Email worker error:", str(e)[:400], flush=True)

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    run_loop()
