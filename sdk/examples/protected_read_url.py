import json
import sys
from pathlib import Path

sys.path.append("sdk")

from sentinel_agent import SentinelAgentClient


def sentinel_protected_read_url(base_url: str, agent_file: str, target: str, method: str = "GET"):
    agent = json.loads(Path(agent_file).read_text())

    client = SentinelAgentClient(
        base_url=base_url,
        agent_id=agent["agent_id"],
        priv_b64=agent["priv_b64"],
    )

    return client.analyze({
        "type": "read_url",
        "target": target,
        "method": method,
    })


if __name__ == "__main__":
    resp = sentinel_protected_read_url(
        base_url="https://sentinelsca.com",
        agent_file="ed25519_test_agent.json",
        target="https://example.com/health",
        method="GET",
    )
    print(json.dumps(resp, indent=2))
