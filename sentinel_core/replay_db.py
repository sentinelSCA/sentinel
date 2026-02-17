import os
import sqlite3
import time
from typing import Optional

DEFAULT_DB_PATH = os.getenv("SENTINEL_DB_PATH", "sentinel.db")


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def ensure_schema(db_path: Optional[str] = None) -> str:
    path = db_path or DEFAULT_DB_PATH
    conn = _connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_nonces (
                nonce TEXT PRIMARY KEY,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_created_at ON replay_nonces(created_at)")
        conn.commit()
    finally:
        conn.close()
    return path


def cleanup(db_path: str, older_than_unix: float) -> int:
    conn = _connect(db_path)
    try:
        cur = conn.execute("DELETE FROM replay_nonces WHERE created_at < ?", (older_than_unix,))
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def check_and_set(db_path: str, nonce: str, ttl_seconds: int) -> bool:
    """
    Returns True if nonce is NEW (inserted).
    Returns False if nonce already exists (replay).
    """
    now = time.time()
    cutoff = now - float(ttl_seconds)

    conn = _connect(db_path)
    try:
        # cleanup old nonces
        conn.execute("DELETE FROM replay_nonces WHERE created_at < ?", (cutoff,))

        try:
            conn.execute("INSERT INTO replay_nonces(nonce, created_at) VALUES(?, ?)", (nonce, now))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    finally:
        conn.close()
