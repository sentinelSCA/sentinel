import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel_ledger import LEDGER_FILE
from sentinel_timeline import TIMELINE_FILE


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def find_report_by_event_id(event_id: str) -> Optional[Dict[str, Any]]:
    for row in reversed(_read_jsonl(LEDGER_FILE)):
        report = row.get("report", {})
        if report.get("event_id") == event_id:
            return row
    return None


def find_timeline_event(event_id: str) -> Optional[Dict[str, Any]]:
    for row in reversed(_read_jsonl(TIMELINE_FILE)):
        if row.get("event_id") == event_id:
            return row
    return None


def replay_event(event_id: str) -> Dict[str, Any]:
    ledger_row = find_report_by_event_id(event_id)
    timeline_row = find_timeline_event(event_id)

    if not ledger_row:
        return {
            "found": False,
            "event_id": event_id,
            "error": "Event not found in ledger",
        }

    report = ledger_row.get("report", {})
    return {
        "found": True,
        "event_id": event_id,
        "report": report,
        "ledger_hash": ledger_row.get("ledger_hash", ""),
        "timeline_event": timeline_row,
        "summary": {
            "agent": report.get("agent", ""),
            "decision": report.get("decision", ""),
            "action_type": (report.get("action", {}) or {}).get("type", ""),
            "target": (report.get("action", {}) or {}).get("target", ""),
            "timestamp": report.get("timestamp", ""),
            "risk_score": report.get("risk_score", 0.0),
        },
    }
