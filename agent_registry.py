import os
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def register_agent(agent_id: str, pub_b64: str):
    r.set(f"agents:pubkey:{agent_id}", pub_b64)

def get_pubkey(agent_id: str) -> str | None:
    return r.get(f"agents:pubkey:{agent_id}")

def revoke_agent(agent_id: str):
    r.sadd("agents:revoked", agent_id)

def is_revoked(agent_id: str) -> bool:
    return r.sismember("agents:revoked", agent_id)
