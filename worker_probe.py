import os
import time
import json
import redis
import urllib.request
import urllib.error
from urllib.parse import urlparse

# -----------------------------
# Config
# -----------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()
INCIDENTS_Q = (os.getenv("OPS_INCIDENTS_Q", "ops:incidents") or "ops:incidents").strip()

POLL_SEC = float((os.getenv("PROBE_POLL_SEC", "15") or "15").strip())
TIMEOUT_SEC = float((os.getenv("PROBE_TIMEOUT_SEC", "3") or "3").strip())

# consecutive failures required to flip to fail
FAIL_THRESHOLD = int((os.getenv("FAIL_THRESHOLD", "2") or "2").strip())

# Comma-separated list like:
# PROBE_TARGETS=sentinel-api=http://sentinel-api:8001/health,redis=http://redis:...
PROBE_TARGETS = (os.getenv("PROBE_TARGETS", "sentinel-api=http://sentinel-api:8001/health") or "").strip()

# Redis keys:
# ops:probe:state:<service> -> ok|fail
# ops:probe:failcount:<service> -> integer
STATE_KEY_PREFIX = os.getenv("PROBE_STATE_PREFIX", "ops:probe:state:").strip() or "ops:probe:state:"
FAILCOUNT_KEY_PREFIX = os.getenv("PROBE_FAILCOUNT_PREFIX", "ops:probe:failcount:").strip() or "ops:probe:failcount:"

r = redis.from_url(REDIS_URL, decode_responses=True)


def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def parse_targets(s: str):
    out = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        name, url = part.split("=", 1)
        name = name.strip()
        url = url.strip()
        if name and url:
            out.append((name, url))
    return out


def http_probe(url: str, timeout: float):
    """
    Returns (ok: bool, status: str|int, err: str)
    - ok True means HTTP 200-299.
    - status is HTTP code when available, else "".
    - err is non-empty on failure.
    """
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            ok = 200 <= int(code) < 300
            return ok, str(code), ""
    except urllib.error.HTTPError as e:
        return False, str(getattr(e, "code", "")), f"HTTPError: {e}"
    except urllib.error.URLError as e:
        return False, "", f"URLError: {e}"
    except Exception as e:
        return False, "", f"Exception: {e}"


def emit_incident(service: str, url: str, status: str, error: str):
    ts = int(time.time())
    incident = {
        "incident_id": f"inc_{ts}_{service}",
        "ts": ts,
        "service": service,
        "kind": "api_unreachable",
        "severity": "high",
        "evidence": {
            "url": url,
            "status": status,
            "error": (error or "")[:300],
        },
    }
    r.rpush(INCIDENTS_Q, jdump(incident))


def run():
    targets = parse_targets(PROBE_TARGETS)

    print("probe-worker started.", flush=True)
    print("REDIS_URL   =", REDIS_URL, flush=True)
    print("INCIDENTS_Q =", INCIDENTS_Q, flush=True)
    print("POLL_SEC    =", POLL_SEC, flush=True)
    print("TIMEOUT_SEC =", TIMEOUT_SEC, flush=True)
    print("FAIL_THRESHOLD =", FAIL_THRESHOLD, flush=True)
    print("TARGETS     =", targets, flush=True)

    if not targets:
        print("No targets configured. Set PROBE_TARGETS.", flush=True)
        while True:
            time.sleep(POLL_SEC)

    while True:
        for svc, url in targets:
            state_key = f"{STATE_KEY_PREFIX}{svc}"
            fc_key = f"{FAILCOUNT_KEY_PREFIX}{svc}"

            prev_state = (r.get(state_key) or "unknown").strip()

            ok, status, err = http_probe(url, TIMEOUT_SEC)

            # Update failcount
            if ok:
                failcount = 0
                r.set(fc_key, "0")
                now_state = "ok"
            else:
                try:
                    failcount = int(r.get(fc_key) or "0")
                except Exception:
                    failcount = 0
                failcount += 1
                r.set(fc_key, str(failcount))

                # only become "fail" once threshold reached
                if failcount >= FAIL_THRESHOLD:
                    now_state = "fail"
                else:
                    # still considered ok until threshold reached
                    now_state = "ok"

                print(f"fail detected ({failcount}/{FAIL_THRESHOLD}) for {svc}", flush=True)

            # EDGE TRIGGER:
            # emit only on ok/unknown -> fail transition
            if now_state == "fail" and prev_state != "fail":
                emit_incident(svc, url, status, err)
                print(f"incident emitted: {svc}", flush=True)

            # Optional recovery log (no incident)
            if prev_state == "fail" and now_state == "ok":
                print(f"state: {svc} -> ok", flush=True)

            # Always store current state
            r.set(state_key, now_state)

        time.sleep(POLL_SEC)


if __name__ == "__main__":
    run()
