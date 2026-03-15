import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

LEDGER_FILE = Path("audit/ai_action_ledger.jsonl")


def _ensure_parent() -> None:
    LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)


def _canonical_report(report: Dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_ledger_hash(previous_hash: str, report: Dict[str, Any]) -> str:
    material = f"{previous_hash}|{_canonical_report(report)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def get_previous_hash() -> str:
    if not LEDGER_FILE.exists():
        return ""
    try:
        last = ""
        with LEDGER_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if not last:
            return ""
        row = json.loads(last)
        return str(row.get("ledger_hash", "")).strip()
    except Exception:
        return ""


def append_report(report: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_parent()
    previous_hash = get_previous_hash()
    report = dict(report)
    if not report.get("previous_hash"):
        report["previous_hash"] = previous_hash
    ledger_hash = compute_ledger_hash(report["previous_hash"], report)
    row = {
        "report": report,
        "ledger_hash": ledger_hash,
    }
    with LEDGER_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def read_ledger(limit: int = 50) -> List[Dict[str, Any]]:
    if not LEDGER_FILE.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with LEDGER_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:]


def verify_ledger() -> bool:
    if not LEDGER_FILE.exists():
        return True

    expected_previous = ""
    with LEDGER_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            report = row.get("report", {})
            stored_hash = str(row.get("ledger_hash", "")).strip()
            report_previous = str(report.get("previous_hash", "")).strip()

            if report_previous != expected_previous:
                return False

            computed = compute_ledger_hash(report_previous, report)
            if computed != stored_hash:
                return False

            expected_previous = stored_hash

    return True
