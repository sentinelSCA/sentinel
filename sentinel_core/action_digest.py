import hashlib
import json


def canonical_action_digest(command: str) -> str:
    """
    Produce a deterministic SHA256 digest of an action command.
    """

    try:
        obj = json.loads(command)
    except Exception:
        obj = {"raw": command}

    normalized = json.dumps(obj, sort_keys=True, separators=(",", ":"))

    return hashlib.sha256(normalized.encode()).hexdigest()
