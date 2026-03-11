from typing import Tuple, Dict, Any


def score_action(action: Dict[str, Any]) -> Tuple[str, float, str]:
    """
    Returns (risk_level, risk_score, reason)
    """

    action_type = str(action.get("type", "unknown"))
    target = str(action.get("target", ""))

    # Low-risk actions
    if action_type == "ping":
        return "low", 0.05, "Connectivity test."

    if action_type == "health_check":
        return "low", 0.08, "System health check."

    # Medium-risk actions
    if action_type == "restart_service" and target == "sentinel-api":
        return "medium", 0.55, "Restart affects control-plane availability."

    if action_type == "scale_worker":
        return "medium", 0.60, "Scaling workers changes execution capacity."

    # High-risk actions
    if action_type == "restart_service" and target == "redis":
        return "high", 0.90, "Restart affects state and queue availability."

    if action_type == "modify_policy":
        return "high", 0.92, "Policy changes affect security decisions."

    # Critical actions
    if action_type in ("delete_database", "drop_table", "shutdown_cluster"):
        return "critical", 0.99, "Destructive infrastructure operation."

    # Default
    return "medium", 0.50, "Unknown action requires caution."
