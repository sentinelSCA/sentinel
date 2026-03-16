import json
import time
from pathlib import Path
from typing import Dict, Any, List

CONTACT_FILE = Path("audit/contact_requests.jsonl")


def _ensure_parent() -> None:
    CONTACT_FILE.parent.mkdir(parents=True, exist_ok=True)


def save_contact_request(data: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_parent()
    row = {
        "id": f"contact_{int(time.time())}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "name": str(data.get("name", "")).strip(),
        "email": str(data.get("email", "")).strip(),
        "company": str(data.get("company", "")).strip(),
        "use_case": str(data.get("use_case", "")).strip(),
        "message": str(data.get("message", "")).strip(),
    }
    with CONTACT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def read_contact_requests(limit: int = 50) -> List[Dict[str, Any]]:
    if not CONTACT_FILE.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with CONTACT_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:]
