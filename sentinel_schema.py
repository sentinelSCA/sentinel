from typing import Any, Dict, Set


ALLOWED_ACTIONS: Set[str] = {
    "read_url",
    "restart_service",
    "scale_service",
    "clear_cache",
}

ACTION_FIELDS: Dict[str, Set[str]] = {
    "read_url": {"type", "target", "method", "reason"},
    "restart_service": {"type", "target", "reason"},
    "scale_service": {"type", "target", "replicas", "reason"},
    "clear_cache": {"type", "target", "reason"},
}

REQUIRED_FIELDS: Dict[str, Set[str]] = {
    "read_url": {"type", "target"},
    "restart_service": {"type", "target"},
    "scale_service": {"type", "target", "replicas"},
    "clear_cache": {"type", "target"},
}


def validate_action_schema(action: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(action, dict):
        raise ValueError("Action must be a JSON object")

    action_type = str(action.get("type", "")).strip()
    if not action_type:
        raise ValueError("Missing action type")

    if action_type not in ALLOWED_ACTIONS:
        raise ValueError(f"Unknown action type: {action_type}")

    allowed = ACTION_FIELDS[action_type]
    required = REQUIRED_FIELDS[action_type]

    extra = set(action.keys()) - allowed
    if extra:
        raise ValueError(f"Unexpected fields for {action_type}: {', '.join(sorted(extra))}")

    missing = [field for field in sorted(required) if field not in action]
    if missing:
        raise ValueError(f"Missing required fields for {action_type}: {', '.join(missing)}")

    cleaned: Dict[str, Any] = {}

    for key in allowed:
        if key in action:
            cleaned[key] = action[key]

    cleaned["type"] = action_type

    if "target" in cleaned:
        cleaned["target"] = str(cleaned["target"]).strip()
        if not cleaned["target"]:
            raise ValueError("Target cannot be empty")

    if action_type == "read_url":
        method = str(cleaned.get("method", "GET")).strip().upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError("read_url method must be GET or HEAD")
        cleaned["method"] = method

    if action_type == "scale_service":
        replicas = cleaned.get("replicas")
        if not isinstance(replicas, int):
            raise ValueError("scale_service replicas must be an integer")
        if replicas < 1 or replicas > 100:
            raise ValueError("scale_service replicas must be between 1 and 100")

    if "reason" in cleaned:
        cleaned["reason"] = str(cleaned["reason"]).strip()

    return cleaned
