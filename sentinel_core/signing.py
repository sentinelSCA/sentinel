import os
import hmac
import hashlib
import json
from typing import Any, Dict, Tuple


SIGNING_SCHEME = "hmac-sha256"
DEFAULT_KEY_ID = "local-dev-key-1"


def canonical_json(payload: Dict[str, Any]) -> bytes:
    # Stable ordering so signatures are reproducible
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_payload(payload: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Returns: (signature_hex, signing_scheme, key_id)
    """
    secret = os.getenv("SENTINEL_SIGNING_SECRET", "")
    if not secret:
        # If secret isn't set, we still return empty signature fields (safe default).
        return "", SIGNING_SCHEME, DEFAULT_KEY_ID

    msg = canonical_json(payload)
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return sig, SIGNING_SCHEME, os.getenv("SENTINEL_SIGNING_KEY_ID", DEFAULT_KEY_ID)
