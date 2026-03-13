import os
import json
import time
import uuid
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone

import redis
from dotenv import load_dotenv

load_dotenv(".env")

# -----------------------------
# CONFIG
# -----------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()

IN_QUEUE = os.getenv("EMAIL_PUBLISH_QUEUE", "tasks:publish:email").strip()
DELAYED_ZSET = os.getenv("EMAIL_PUBLISH_DELAYED_ZSET", "tasks:publish:email:delayed").strip()
DEAD_QUEUE = os.getenv("EMAIL_PUBLISH_DEAD_Q", "tasks:publish:email:dead").strip()

PUBLISH_MODE = os.getenv("EMAIL_PUBLISH_MODE", "smtp").strip().lower()  # smtp | file

OUT_DIR = os.getenv("EMAIL_OUT_DIR", "published_email").strip()
os.makedirs(OUT_DIR, exist_ok=True)

DEFAULT_TO = os.getenv("EMAIL_DEFAULT_TO", "").strip()

# SMTP
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587").strip() or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", f"Sentinel SCA <{SMTP_USER}>").strip()

# Hardening knobs
MAX_PER_DAY = int(os.getenv("EMAIL_MAX_PER_DAY", "10").strip() or "10")
IDEMP_TTL_SEC = int(os.getenv("EMAIL_IDEMP_TTL_SEC", str(7 * 24 * 3600)).strip() or str(7 * 24 * 3600))

RETRY_MAX = int(os.getenv("EMAIL_RETRY_MAX", "5").strip() or "5")
# backoff schedule (seconds): 1m, 5m, 15m, 1h, 3h
RETRY_BACKOFF = [60, 300, 900, 3600, 10800]

POLL_SEC = float(os.getenv("EMAIL_PUBLISH_POLL_SEC", "0.5").strip() or "0.5")
BLPOP_TIMEOUT = int(os.getenv("EMAIL_PUBLISH_BLPOP_TIMEOUT", "2").strip() or "2")

AGENT_ID = os.getenv("AGENT_ID", os.getenv("EMAIL_PUBLISH_AGENT_ID", "worker:email_publish")).strip()

r = redis.from_url(REDIS_URL, decode_responses=True)

# -----------------------------
# Helpers
# -----------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def utc_day_key(prefix: str) -> str:
    # Daily bucket in UTC
    day = time.strftime("%Y%m%d", time.gmtime())
    return f"{prefix}:{day}"

def seconds_until_utc_midnight() -> int:
    now = int(time.time())
    # next midnight UTC
    g = time.gmtime(now)
    # seconds since midnight
    since = g.tm_hour * 3600 + g.tm_min * 60 + g.tm_sec
    return max(1, 86400 - since)

def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

def safe_jload(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None

def claim_idempotency(task_id: str) -> bool:
    """
    True if we successfully claimed this task_id (first time).
    """
    if not task_id:
        return False
    key = f"email:sent:{task_id}"
    ok = r.set(key, "1", nx=True, ex=IDEMP_TTL_SEC)
    return bool(ok)

def rate_allow() -> tuple[bool, int]:
    """
    Returns (allowed, current_count_after_increment_if_allowed)
    """
    key = utc_day_key("email:rate")
    current = r.get(key)
    cur = int(current) if current and current.isdigit() else 0

    if cur >= MAX_PER_DAY:
        return False, cur

    new_val = r.incr(key)
    if new_val == 1:
        r.expire(key, seconds_until_utc_midnight())
    return True, int(new_val)

def defer(task: dict, delay_sec: int, reason: str):
    due = int(time.time()) + int(delay_sec)
    task = dict(task)
    task["deferred_at"] = now_iso()
    task["deferred_reason"] = reason
    r.zadd(DELAYED_ZSET, {jdump(task): due})

def dead_letter(task: dict, reason: str):
    task = dict(task)
    task["dead_at"] = now_iso()
    task["dead_reason"] = reason
    r.rpush(DEAD_QUEUE, jdump(task))

def reap_delayed(limit: int = 25) -> int:
    """
    Move ready delayed items back to IN_QUEUE.
    """
    now = int(time.time())
    items = r.zrangebyscore(DELAYED_ZSET, 0, now, start=0, num=limit)
    moved = 0
    for raw in items:
        if r.zrem(DELAYED_ZSET, raw):
            r.rpush(IN_QUEUE, raw)
            moved += 1
    return moved

def send_smtp(to_addr: str, subject: str, body: str):
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

def fallback_save(task: dict, note: str):
    path = os.path.join(OUT_DIR, f"{uuid.uuid4()}.json")
    rec = {
        "published_at": now_iso(),
        "agent": AGENT_ID,
        "mode": "file",
        "note": note,
        "task": task,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    return path

# -----------------------------
# Main loop
# -----------------------------
def run_loop():
    print("Email publish worker started (Redis hardened).", flush=True)
    print("REDIS_URL    =", REDIS_URL, flush=True)
    print("IN_QUEUE     =", IN_QUEUE, flush=True)
    print("DELAYED_ZSET =", DELAYED_ZSET, flush=True)
    print("DEAD_QUEUE   =", DEAD_QUEUE, flush=True)
    print("PUBLISH_MODE =", PUBLISH_MODE, flush=True)
    print("MAX_PER_DAY  =", MAX_PER_DAY, flush=True)

    if PUBLISH_MODE == "smtp":
        print("SMTP_HOST =", SMTP_HOST, flush=True)
        print("SMTP_PORT =", SMTP_PORT, flush=True)
        print("SMTP_USER =", SMTP_USER, flush=True)
        print("SMTP_FROM =", SMTP_FROM, flush=True)

    while True:
        try:
            # periodically requeue delayed
            reap_delayed()

            item = r.blpop(IN_QUEUE, timeout=BLPOP_TIMEOUT)
            if not item:
                time.sleep(POLL_SEC)
                continue

            _, raw = item
            task = safe_jload(raw) if raw and raw.strip().startswith("{") else safe_jload(raw)
            if not isinstance(task, dict):
                dead_letter({"raw": (raw or "")[:500]}, "invalid_task_json")
                continue

            task_id = (task.get("id") or "").strip()
            to_addr = (task.get("to") or DEFAULT_TO or "").strip()
            subject = (task.get("subject") or "No subject").strip()
            body = (task.get("body") or "").strip()

            # Must have destination
            if not to_addr:
                dead_letter(task, "missing_to_and_no_EMAIL_DEFAULT_TO")
                continue

            # Must have content
            if not body:
                dead_letter(task, "missing_body")
                continue

            # Idempotency
            if task_id and not claim_idempotency(task_id):
                # already sent recently; skip silently
                continue

            # Rate limit
            allowed, cur = rate_allow()
            if not allowed:
                # defer until tomorrow UTC midnight-ish
                defer(task, seconds_until_utc_midnight() + 5, "rate_limited")
                continue

            # Publish
            if PUBLISH_MODE == "file":
                path = fallback_save(task, note=f"file_mode_saved (rate_count={cur})")
                print("Email saved →", path, flush=True)
                continue

            # SMTP mode
            try:
                send_smtp(to_addr, subject, body)
                print(f"Email sent → sent:{to_addr}", flush=True)
            except Exception as e:
                # retry with backoff
                attempts = int(task.get("attempts") or 0) + 1
                task["attempts"] = attempts
                err = str(e)[:300]

                if attempts <= RETRY_MAX:
                    backoff = RETRY_BACKOFF[min(attempts - 1, len(RETRY_BACKOFF) - 1)]
                    task["last_error"] = err
                    defer(task, backoff, f"smtp_retry_{attempts}")
                    # also save a local record for audit/debug
                    path = fallback_save(task, note=f"smtp_failed_deferred:{err}")
                    print("SMTP failed; deferred + saved →", path, flush=True)
                else:
                    task["last_error"] = err
                    dead_letter(task, f"smtp_failed_gave_up:{err}")
                    path = fallback_save(task, note=f"smtp_failed_dead:{err}")
                    print("SMTP failed; dead-letter + saved →", path, flush=True)

        except Exception as e:
            print("email-publish loop error:", str(e)[:300], flush=True)
            time.sleep(1)

if __name__ == "__main__":
    run_loop()
