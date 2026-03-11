# sentinel-agent

Minimal Python SDK for submitting signed agent actions to Sentinel.

## Install

pip install .

## Example

from sentinel_agent import SentinelAgentClient

client = SentinelAgentClient(
    base_url="https://sentinelsca.com",
    agent_id="agent_xxx",
    priv_b64="BASE64_PRIVATE_KEY",
)

resp = client.analyze({
    "type": "read_url",
    "target": "https://example.com/health",
    "method": "GET",
})

print(resp)
