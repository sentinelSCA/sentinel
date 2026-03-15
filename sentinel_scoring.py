from collections import defaultdict
from typing import Any, Dict, List

from sentinel_timeline import read_timeline


def compute_agent_security_scores(limit: int = 200) -> Dict[str, Dict[str, Any]]:
    events: List[Dict[str, Any]] = read_timeline(limit=limit)
    by_agent: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        agent = str(event.get("agent", "")).strip()
        if not agent:
            continue
        by_agent[agent].append(event)

    results: Dict[str, Dict[str, Any]] = {}

    for agent, agent_events in by_agent.items():
        score = 100.0
        total = len(agent_events)
        allow_count = 0
        review_count = 0
        deny_count = 0
        high_risk_count = 0

        for ev in agent_events:
            decision = str(ev.get("decision", "")).strip().upper()
            risk_score = float(ev.get("risk_score", 0.0) or 0.0)

            if decision == "ALLOW":
                allow_count += 1
            elif decision == "REVIEW":
                review_count += 1
                score -= 5
            elif decision == "DENY":
                deny_count += 1
                score -= 10

            if risk_score >= 0.8:
                high_risk_count += 1
                score -= 2

        if score < 0:
            score = 0.0

        if score >= 90:
            rating = "excellent"
        elif score >= 75:
            rating = "good"
        elif score >= 50:
            rating = "risky"
        else:
            rating = "dangerous"

        results[agent] = {
            "agent": agent,
            "score": round(score, 2),
            "rating": rating,
            "events_total": total,
            "allow_count": allow_count,
            "review_count": review_count,
            "deny_count": deny_count,
            "high_risk_count": high_risk_count,
        }

    return results
