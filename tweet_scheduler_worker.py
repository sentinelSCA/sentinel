import os, time, json
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()
OUT_Q = os.getenv("SCHED_WRITER_Q", "tasks:writer").strip()

# local time schedule
MORNING_H = int(os.getenv("TWEET_MORNING_HOUR", "9"))
EVENING_H = int(os.getenv("TWEET_EVENING_HOUR", "18"))
MINUTE = int(os.getenv("TWEET_MINUTE", "0"))

TONE = os.getenv("TWEET_TONE", "professional").strip()

r = redis.from_url(REDIS_URL, decode_responses=True)

TEMPLATES = [
  "Sentinel SCA: signed requests + deterministic policy decisions + audit-chain integrity for autonomous agents.",
  "Sentinel SCA: sandbox isolation, allowlisted commands, rate limiting, and reputation tracking — safe-by-design automation.",
  "Sentinel SCA: policy gateway between agents and execution. Verifiable decisions, tamper-evident audit, operational safety.",
]

def push(topic: str):
    job = {"topic": topic, "tone": TONE}
    r.rpush(OUT_Q, json.dumps(job))
    print("enqueued writer job:", topic[:80], flush=True)

def run():
    print("tweet-scheduler started.", flush=True)
    print("schedule:", f"{MORNING_H}:{MINUTE:02d} and {EVENING_H}:{MINUTE:02d}", flush=True)

    last_key = None
    i = 0

    while True:
        now = time.localtime()
        key = (now.tm_yday, now.tm_hour, now.tm_min)

        if now.tm_min == MINUTE and now.tm_hour in (MORNING_H, EVENING_H):
            if key != last_key:
                topic = TEMPLATES[i % len(TEMPLATES)]
                i += 1
                push(topic)
                last_key = key

        time.sleep(10)

if __name__ == "__main__":
    run()

