import json
import os
import time
import hashlib
from typing import Any, Dict

AUDIT_DIR = "/app/audit"
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit.jsonl")


def ensure_audit_dir():
    os.makedirs(AUDIT_DIR, exist_ok=True)


def _last_hash() -> str | None:
    """
    Return hash of the last non-empty record in the audit log.
    """
    if not os.path.exists(AUDIT_FILE):
        return None

    try:
        with open(AUDIT_FILE, "rb") as f:
            lines = f.read().splitlines()
        for raw in reversed(lines):
            raw = raw.strip()
            if not raw:
                continue
            rec = json.loads(raw.decode("utf-8"))
            return rec.get("hash")
    except Exception:
        return None

    return None

def _hash_record(rec: Dict[str, Any]) -> str:
    data = json.dumps(rec, sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


def write_audit_log(event_type: str, payload: Dict[str, Any]):
    ensure_audit_dir()

    prev_hash = _last_hash()

    record = {
        "ts": int(time.time()),
        "event": event_type,
        "prev_hash": prev_hash,
        **payload,
    }

    record_hash = _hash_record(record)
    record["hash"] = record_hash

    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
