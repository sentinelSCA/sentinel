import json
from pathlib import Path
from typing import Dict, List


CAPABILITIES_FILE = Path("capabilities.json")


def load_capabilities() -> Dict[str, List[str]]:
    if not CAPABILITIES_FILE.exists():
        return {}
    try:
        data = json.loads(CAPABILITIES_FILE.read_text())
    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    cleaned: Dict[str, List[str]] = {}
    for agent_id, caps in data.items():
        if not isinstance(agent_id, str):
            continue
        if not isinstance(caps, list):
            continue
        cleaned[agent_id] = [str(c).strip() for c in caps if str(c).strip()]
    return cleaned


def save_capabilities(data: Dict[str, List[str]]) -> None:
    CAPABILITIES_FILE.write_text(json.dumps(data, indent=2, sort_keys=True))


def get_agent_capabilities(agent_id: str) -> List[str]:
    data = load_capabilities()
    return data.get(agent_id, [])


def has_capability(agent_id: str, capability: str) -> bool:
    if not agent_id or not capability:
        return False
    allowed = get_agent_capabilities(agent_id)
    return capability in allowed


def grant_capability(agent_id: str, capability: str) -> None:
    if not agent_id or not capability:
        return
    data = load_capabilities()
    caps = set(data.get(agent_id, []))
    caps.add(capability)
    data[agent_id] = sorted(caps)
    save_capabilities(data)


def revoke_capability(agent_id: str, capability: str) -> None:
    data = load_capabilities()
    caps = set(data.get(agent_id, []))
    if capability in caps:
        caps.remove(capability)
    data[agent_id] = sorted(caps)
    save_capabilities(data)
