import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()
QUEUE_SIGNING_SECRET = os.getenv("QUEUE_SIGNING_SECRET", "").strip()

r = redis.from_url(REDIS_URL, decode_responses=True)

def _jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _hmac_sig(data: str) -> str:
    return hmac.new(QUEUE_SIGNING_SECRET.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()

def _wrap(payload: dict) -> dict:
    """
    Envelope format:
      { "v":1, "ts":"...", "payload":{...}, "sig":"..." }
    """
    if not QUEUE_SIGNING_SECRET:
        return payload  # signing disabled

    ts = _now_iso()
    body = {"v": 1, "ts": ts, "payload": payload}
    sig = _hmac_sig(_jdump(body))
    body["sig"] = sig
    return body

def _unwrap(obj: dict) -> dict | None:
    if not QUEUE_SIGNING_SECRET:
        return obj

    # must be envelope
    if not isinstance(obj, dict) or "payload" not in obj or "sig" not in obj or "ts" not in obj:
        return None

    sig = str(obj.get("sig") or "")
    unsigned = {"v": obj.get("v", 1), "ts": obj.get("ts"), "payload": obj.get("payload")}
    expected = _hmac_sig(_jdump(unsigned))
    if not hmac.compare_digest(expected, sig):
        return None

    payload = obj.get("payload")
    return payload if isinstance(payload, dict) else None

def qpush(queue_name: str, payload: dict) -> None:
    msg = _wrap(payload)
    r.rpush(queue_name, _jdump(msg))

def qpop(queue_name: str, timeout: int = 0) -> dict | None:
    """
    BLPOP if timeout > 0 else LPOP.
    Returns dict payload or None if empty/invalid/tampered.
    """
    if timeout and timeout > 0:
        item = r.blpop(queue_name, timeout=timeout)
        if not item:
            return None
        _, raw = item
    else:
        raw = r.lpop(queue_name)
        if raw is None:
            return None

    try:
        obj = json.loads(raw)
    except Exception:
        return None

    return _unwrap(obj)
