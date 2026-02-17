import hashlib
import os


def variable_timestamp(command: str, timestamp: str, agent_id: str) -> str:
    """
    Produces a stable-but-unique token that changes with:
      - command
      - timestamp (from request)
      - agent_id
    This avoids collisions across agents and repeated commands.
    """
    secret_salt = os.getenv("SENTINEL_VT_SALT", "sentinel-vt-default-salt")
    raw = f"{agent_id}|{timestamp}|{command}|{secret_salt}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]
