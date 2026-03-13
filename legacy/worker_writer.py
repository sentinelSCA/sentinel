import os
import json
import time
import uuid
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

from queue_redis import qpop, qpush
from llm_local import ollama_generate
from agent_identity import sign_payload

# --------------------------------------------------
# CONFIG
# --------------------------------------------------

load_dotenv(".env")

# Use container-safe defaults
SENTINEL_URL = os.getenv("SENTINEL_URL", "http://sentinel-api:8001/analyze").strip()
API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()

AGENT_ID = os.getenv("AGENT_ID", "").strip()
AGENT_PRIV_B64 = os.getenv("AGENT_PRIV_B64", "").strip()

SENTINEL_SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "").strip()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3").strip() or "llama3"
HTTP_TIMEOUT = int(os.getenv("SENTINEL_HTTP_TIMEOUT", "10").strip() or "10")

IN_QUEUE = os.getenv("WRITER_IN_QUEUE", "tasks:writer").strip()
VERIFY_QUEUE = os.getenv("WRITER_VERIFY_QUEUE", "tasks:verify").strip()

OUTPUT_DIR = os.getenv("WRITER_OUTPUT_DIR", "outputs_writer").strip() or "outputs_writer"
os.makedirs(OUTPUT_DIR, exist_ok=True)

if not API_KEY:
    raise RuntimeError("Missing SENTINEL_API_KEY in .env")
if not AGENT_ID or not AGENT_PRIV_B64:
    raise RuntimeError("Missing AGENT_ID or AGENT_PRIV_B64 in .env")
if not SENTINEL_SIGNING_SECRET:
    raise RuntimeError("Missing SENTINEL_SIGNING_SECRET in .env")


def log(*args):
    print(*args, flush=True)


# --------------------------------------------------
# SENTINEL CALL (HMAC + Ed25519)
# --------------------------------------------------

def call_sentinel(command: str) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    ts_unix = str(int(time.time()))

    payload = {
        "agent_id": AGENT_ID,
        "command": command,
        "timestamp": ts,
        "reputation": 0.0,
    }

    # HMAC signature (Sentinel signing secret)
    hmac_body = json.dumps(
        {"agent_id": AGENT_ID, "command": command, "timestamp": ts, "ts_unix": ts_unix},
        sort_keys=True,
        separators=(",", ":"),
    )

    import hmac, hashlib
    x_sig = hmac.new(
        SENTINEL_SIGNING_SECRET.encode("utf-8"),
        hmac_body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Ed25519 signature (agent identity)
    agent_sig_payload = {
        "agent_id": AGENT_ID,
        "command": command,
        "timestamp": ts,
        "ts_unix": ts_unix,
    }
    agent_sig = sign_payload(
        AGENT_PRIV_B64,
        json.dumps(agent_sig_payload, sort_keys=True, separators=(",", ":")),
    )

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Timestamp-Unix": ts_unix,
        "X-Signature": x_sig,
        "X-Agent-Signature": agent_sig,
    }

    r = requests.post(SENTINEL_URL, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


# --------------------------------------------------
# MAIN LOOP
# --------------------------------------------------

def run_loop():
    log("Writer agent started... (Redis queue mode)")
    log("IN_QUEUE     =", IN_QUEUE)
    log("VERIFY_QUEUE =", VERIFY_QUEUE)
    log("SENTINEL_URL =", SENTINEL_URL)
    log("OLLAMA_MODEL =", OLLAMA_MODEL)
    log("OUTPUT_DIR   =", OUTPUT_DIR)

    while True:
        job = qpop(IN_QUEUE, timeout=5)
        if not job:
            continue

        topic = (job.get("topic") or "").strip()
        tone = (job.get("tone") or "professional").strip()

        if not topic:
            log("Writer: missing topic, dropped job:", job)
            continue

        prompt = f"Write a {tone} update about: {topic}"

        try:
            decision = call_sentinel(prompt)
            if decision.get("decision") != "allow":
                log("Writer blocked by Sentinel:", decision.get("reason") or decision)
                continue

            text = ollama_generate(prompt, model=OLLAMA_MODEL)
            text = (text or "").strip()
            if not text:
                log("Writer: LLM returned empty text")
                continue

            filename = f"{uuid.uuid4()}.txt"
            path = os.path.join(OUTPUT_DIR, filename)

            with open(path, "w", encoding="utf-8") as f:
                f.write(text)

            log("Writer generated:", path)

            # enqueue verify task
            qpush(VERIFY_QUEUE, {"source_path": path})

        except Exception as e:
            log("Writer error:", repr(e))

        time.sleep(0.2)


if __name__ == "__main__":
    run_loop()
