import os, json, time, uuid
from dotenv import load_dotenv
from datetime import datetime, timezone

from queue_redis import qpop, qpush

load_dotenv(".env")

AGENT_ID = os.getenv("VERIFIER_AGENT_ID", "worker:verifier").strip()

IN_QUEUE = os.getenv("VERIFY_QUEUE", "tasks:verify").strip()
OUT_TWITTER = os.getenv("OUT_TWITTER_QUEUE", "tasks:publish:twitter").strip()
OUT_EMAIL = os.getenv("OUT_EMAIL_QUEUE", "tasks:publish:email").strip()

APPROVED_DIR = "approved"
REJECTED_DIR = "rejected"
os.makedirs(APPROVED_DIR, exist_ok=True)
os.makedirs(REJECTED_DIR, exist_ok=True)

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def verify_against_readme(text: str) -> dict:
    readme = ""
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            readme = f.read().lower()
    except Exception:
        pass

    t = (text or "").lower()

    banned_claims = ["guaranteed", "100% secure", "we already integrated with", "mainnet live"]
    if any(x in t for x in banned_claims):
        return {"decision": "reject", "reason": "Contains strong/unsafe claims."}

    must_be_in_readme = ["signed", "audit", "policy", "sandbox", "rate", "reputation", "telegram", "gateway"]
    score = sum(1 for k in must_be_in_readme if k in t and k in readme)

    if score < 2:
        return {"decision": "reject", "reason": "Not grounded enough in README context."}

    return {"decision": "approve", "reason": "Looks grounded in README."}

def run_loop():
    print("Verifier worker started (Redis queue mode).", flush=True)
    print("IN_QUEUE =", IN_QUEUE, flush=True)
    print("OUT_EMAIL =", OUT_EMAIL, flush=True)
    print("OUT_TWITTER =", OUT_TWITTER, flush=True)

    while True:
        job = qpop(IN_QUEUE, timeout=5)
        if not job:
            time.sleep(1)
            continue

        ts = _now_iso()
        kind = (job.get("kind") or "").strip()
        job_id = (job.get("id") or f"verify_{uuid.uuid4()}").strip()

        # ✅ verify BODY directly (no container file dependency)
        body = (job.get("body") or "").strip()
        if not body:
            print("Missing body:", job_id, flush=True)
            continue

        verdict = verify_against_readme(body)

        out_dir = APPROVED_DIR if verdict["decision"] == "approve" else REJECTED_DIR
        out_path = os.path.join(out_dir, f"{uuid.uuid4()}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"agent_id": AGENT_ID, "timestamp": ts, "job": job, "verdict": verdict}, f, indent=2)

        print(verdict["decision"].upper(), "→", out_path, "|", verdict["reason"], flush=True)

        if verdict["decision"] != "approve":
            continue

        # publish routing
        if kind == "email":
            qpush(OUT_EMAIL, {
                "id": job_id,
                "to": (job.get("to") or "").strip(),
                "subject": (job.get("subject") or "No subject").strip(),
                "body": body,
                "approved_at": ts,
                "verified_by": AGENT_ID,
            })

        elif kind == "twitter":
            qpush(OUT_TWITTER, {
                "id": job_id,
                "text": body,
                "approved_at": ts,
                "verified_by": AGENT_ID,
            })

        else:
            # unknown kind → do nothing, but still audited in approved/
            pass

if __name__ == "__main__":
    run_loop()
