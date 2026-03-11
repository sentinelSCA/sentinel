import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class SentinelAgentClient:
    base_url: str
    agent_id: str
    priv_b64: str
    timeout: float = 15.0

    def _private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(self.priv_b64))

    def _sign_payload(self, payload: Dict[str, Any]) -> str:
        msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = self._private_key().sign(msg)
        return base64.b64encode(sig).decode("utf-8")

    def analyze(self, command: Dict[str, Any], timestamp: str | None = None) -> Dict[str, Any]:
        ts_unix = str(int(time.time()))
        body = {
            "agent_id": self.agent_id,
            "command": json.dumps(command, separators=(",", ":"), sort_keys=True),
            "timestamp": timestamp or ts_unix,
        }

        signed_payload = {
            "agent_id": body["agent_id"],
            "command": body["command"],
            "timestamp": body["timestamp"],
            "ts_unix": ts_unix,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Timestamp-Unix": ts_unix,
            "X-Signature": self._sign_payload(signed_payload),
        }

        resp = requests.post(
            f"{self.base_url.rstrip('/')}/analyze",
            headers=headers,
            json=body,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()
