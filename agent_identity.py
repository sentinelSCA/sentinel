import base64
import hashlib
import json
import os
import sqlite3
import time
import json
import base64

def sign_payload(payload: dict, priv_b64: str) -> str:
    """
    Returns a base64 signature (Ed25519) over a canonical JSON payload.
    Canonicalization: json.dumps(sort_keys=True, separators=(",", ":"))
    """
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sk = base64.b64decode(priv_b64.encode("utf-8"))

    # Try cryptography first
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.from_private_bytes(sk)
        sig = priv.sign(msg)
        return base64.b64encode(sig).decode("utf-8")
    except ModuleNotFoundError:
        pass

    # Fallback to PyNaCl
    try:
        from nacl.signing import SigningKey
        priv = SigningKey(sk)
        sig = priv.sign(msg).signature
        return base64.b64encode(sig).decode("utf-8")
    except ModuleNotFoundError:
        raise RuntimeError(
            "Missing Ed25519 dependency. Install one of: cryptography OR pynacl."
        )

from typing import Any, Dict, Optional

# ----------------------------
# Storage (SQLite)
# ----------------------------

def _db_path() -> str:
    # Use same DB file as Sentinel if you want one DB
    return os.getenv("SENTINEL_DB_PATH", "sentinel.db")

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def _ensure_schema() -> None:
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                pub_b64   TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                revoked INTEGER NOT NULL DEFAULT 0,
                created_ts INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

# ----------------------------
# Helpers
# ----------------------------

def _normalize_pub(pub_b64: str) -> str:
    pub_b64 = (pub_b64 or "").strip()
    if not pub_b64:
        raise ValueError("pub_b64 is required")

    # Validate it's base64 and decodes to something non-empty
    try:
        raw = base64.b64decode(pub_b64 + "==", validate=False)
    except Exception as e:
        raise ValueError(f"pub_b64 is not valid base64: {e}")

    if not raw or len(raw) < 16:
        raise ValueError("pub_b64 decoded too short (invalid key?)")

    return pub_b64

def agent_id_from_pub(pub_b64: str) -> str:
    # Stable ID derived from pubkey string
    h = hashlib.sha256(pub_b64.encode("utf-8")).hexdigest()[:16]
    return f"agent_{h}"

# ----------------------------
# Public API (what sentinel_api imports)
# ----------------------------

def register_agent(pub_b64: str, display_name: str = "", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    _ensure_schema()
    pub_b64 = _normalize_pub(pub_b64)
    agent_id = agent_id_from_pub(pub_b64)
    display_name = (display_name or "").strip()
    metadata = metadata or {}

    conn = _connect()
    try:
        cur = conn.execute("SELECT agent_id, revoked FROM agents WHERE agent_id = ?", (agent_id,))
        row = cur.fetchone()

        if row:
            # Update existing record (don’t reset created_ts)
            conn.execute(
                """
                UPDATE agents
                SET pub_b64 = ?, display_name = ?, metadata_json = ?
                WHERE agent_id = ?
                """,
                (pub_b64, display_name, json.dumps(metadata, separators=(",", ":"), sort_keys=True), agent_id),
            )
            conn.commit()
        else:
            conn.execute(
                """
                INSERT INTO agents (agent_id, pub_b64, display_name, metadata_json, revoked, created_ts)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (
                    agent_id,
                    pub_b64,
                    display_name,
                    json.dumps(metadata, separators=(",", ":"), sort_keys=True),
                    int(time.time()),
                ),
            )
            conn.commit()

        return {
            "agent_id": agent_id,
            "pub_b64": pub_b64,
            "display_name": display_name,
            "metadata": metadata,
            "revoked": bool(row["revoked"]) if row else False,
        }
    finally:
        conn.close()

def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    _ensure_schema()
    agent_id = (agent_id or "").strip()
    if not agent_id:
        return None

    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT agent_id, pub_b64, display_name, metadata_json, revoked, created_ts FROM agents WHERE agent_id = ?",
            (agent_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "agent_id": row["agent_id"],
            "pub_b64": row["pub_b64"],
            "display_name": row["display_name"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
            "revoked": bool(row["revoked"]),
            "created_ts": int(row["created_ts"]),
        }
    finally:
        conn.close()

def revoke_agent(agent_id: str) -> Dict[str, Any]:
    _ensure_schema()
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise ValueError("agent_id required")

    conn = _connect()
    try:
        cur = conn.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError("Agent not found")

        conn.execute("UPDATE agents SET revoked = 1 WHERE agent_id = ?", (agent_id,))
        conn.commit()
        return {"agent_id": agent_id, "revoked": True}
    finally:
        conn.close()

# ----------------------------
# Optional: your existing keypair generator
# (If you already have one, keep yours; this is a fallback)
# ----------------------------

def generate_keypair() -> Dict[str, str]:
    """
    Fallback generator that DOES NOT create real Ed25519 keys.
    If you already have a real Ed25519 generator in your repo,
    keep it and delete this function.
    """
    # If your project already has a proper Ed25519 generator,
    # DO NOT use this fallback.
    priv = base64.b64encode(os.urandom(32)).decode("utf-8")
    pub = base64.b64encode(os.urandom(32)).decode("utf-8")
    return {"priv_b64": priv, "pub_b64": pub, "agent_id": agent_id_from_pub(pub)}
