import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

# In-memory behavior limits.
# Fine for now; later this can move to Redis.

ACTION_WINDOW_SEC = 60
SENSITIVE_WINDOW_SEC = 3600

DEFAULT_MAX_ACTIONS_PER_MINUTE = 5
DEFAULT_MAX_SENSITIVE_PER_HOUR = 3

SENSITIVE_ACTIONS = {
    "restart_service",
    "scale_service",
    "clear_cache",
}

_action_events: Dict[str, Deque[float]] = defaultdict(deque)
_sensitive_events: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)


def _prune(q: Deque[float], now: float, window_sec: int) -> None:
    cutoff = now - window_sec
    while q and q[0] < cutoff:
        q.popleft()


def check_behavior_limits(agent_id: str, action_type: str) -> Tuple[bool, str]:
    now = time.time()

    # Global action rate
    aq = _action_events[agent_id]
    _prune(aq, now, ACTION_WINDOW_SEC)
    if len(aq) >= DEFAULT_MAX_ACTIONS_PER_MINUTE:
        return False, f"Behavior limit exceeded: max_actions_per_minute={DEFAULT_MAX_ACTIONS_PER_MINUTE}"

    # Sensitive action rate
    if action_type in SENSITIVE_ACTIONS:
        sq = _sensitive_events[(agent_id, action_type)]
        _prune(sq, now, SENSITIVE_WINDOW_SEC)
        if len(sq) >= DEFAULT_MAX_SENSITIVE_PER_HOUR:
            return False, (
                f"Behavior limit exceeded: max_{action_type}_per_hour="
                f"{DEFAULT_MAX_SENSITIVE_PER_HOUR}"
            )

    return True, ""


def record_behavior_event(agent_id: str, action_type: str) -> None:
    now = time.time()

    aq = _action_events[agent_id]
    _prune(aq, now, ACTION_WINDOW_SEC)
    aq.append(now)

    if action_type in SENSITIVE_ACTIONS:
        sq = _sensitive_events[(agent_id, action_type)]
        _prune(sq, now, SENSITIVE_WINDOW_SEC)
        sq.append(now)
