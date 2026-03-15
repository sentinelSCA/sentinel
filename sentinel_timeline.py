import json
from pathlib import Path
from typing import Any, Dict, List

TIMELINE_FILE = Path("audit/ai_action_timeline.jsonl")


def _ensure_parent() -> None:
    TIMELINE_FILE.parent.mkdir(parents=True, exist_ok=True)


def build_timeline_event(report: Dict[str, Any], ledger_hash: str) -> Dict[str, Any]:
    action = report.get("action", {}) if isinstance(report.get("action", {}), dict) else {}
    return {
        "event_id": report.get("event_id", ""),
        "timestamp": report.get("timestamp", ""),
        "agent": report.get("agent", ""),
        "capability": report.get("capability", ""),
        "action_type": action.get("type", ""),
        "target": action.get("target", ""),
        "decision": report.get("decision", ""),
        "risk_score": report.get("risk_score", 0.0),
        "reason": report.get("reason", ""),
        "action_hash": report.get("action_hash", ""),
        "ledger_hash": ledger_hash,
    }


def append_timeline_event(event: Dict[str, Any]) -> None:
    _ensure_parent()
    with TIMELINE_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_timeline(limit: int = 50) -> List[Dict[str, Any]]:
    if not TIMELINE_FILE.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with TIMELINE_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:]
