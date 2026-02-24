import os
import json
import time
import redis
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timezone

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
IN_QUEUE = "tasks:publish:email"
DELAYED_ZSET = "tasks:publish:email:delayed"

EMAIL_MAX_PER_DAY = int(os.getenv("EMAIL_MAX_PER_DAY", "2"))
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
EMAIL_DEFAULT_TO = os.getenv("EMAIL_DEFAULT_TO", SMTP_USER)

r = redis.from_url(REDIS_URL, decode_responses=True)

def today_key():
    return datetime.utcnow().strftime("%Y%m%d")

def rate_key():
    return f"email:rate:{today_key()}"

def already_sent_key(task_id):
    return f"email:sent:{task_id}"

def send_email(to_addr, subject, body):
    msg = MIMEText(body)
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [to_addr], msg.as_string())

def run():
    print("Email publish worker started (Redis queue mode).")
    print("IN_QUEUE =", IN_QUEUE)

    while True:
        job = r.blpop(IN_QUEUE, timeout=5)
        if not job:
            continue

        _, raw = job
        task = json.loads(raw)

        task_id = task.get("id")
        to_addr = task.get("to") or EMAIL_DEFAULT_TO
        subject = task.get("subject", "No subject")
        body = task.get("body", "")

        if not task_id:
            continue

        # Idempotency
        if r.get(already_sent_key(task_id)):
            print("SKIP duplicate:", task_id)
            continue

        # Rate limit
        count = r.incr(rate_key())
        if count == 1:
            r.expire(rate_key(), 86400)

        if count > EMAIL_MAX_PER_DAY:
            print("DEFERRED (rate limit):", task_id)
            r.zadd(DELAYED_ZSET, {
                raw: int(time.time()) + 86400
            })
            continue

        try:
            send_email(to_addr, subject, body)
            r.set(already_sent_key(task_id), 1)
            print("Email sent →", to_addr)
        except Exception as e:
            print("SMTP error:", str(e))

if __name__ == "__main__":
    run()
