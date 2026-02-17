"""
sentinel_cli.py — Sentinel local CLI client (signed requests)

Usage:
  ./venv/bin/python sentinel_cli.py "ls"
  ./venv/bin/python sentinel_cli.py "rm -rf /" --agent-id "cli:habibu"
  echo "ls" | ./venv/bin/python sentinel_cli.py --stdin

Exit codes:
  0 = allow
  2 = deny
  3 = review / warn (if your policy ever returns that)
  1 = client/runtime error (bad config, cannot reach API, etc.)
"""

import os
import sys
import json
import time
import hmac
import hashlib
import argparse
from typing import Any, Dict

import requests
from dotenv import load_dotenv


def canonical_json(obj: Dict[str, Any]) -> bytes:
    # MUST match server: json.dumps(sort_keys=True, separators=(",", ":"))
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign_payload(secret: str, payload: Dict[str, Any]) -> str:
    msg = canonical_json(payload)
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def exit_code_for_decision(decision: str) -> int:
    d = (decision or "").lower().strip()
    if d == "allow":
        return 0
    if d == "deny":
        return 2
    if d in ("review", "warn", "warning"):
        return 3
    return 1


def main() -> int:
    load_dotenv(dotenv_path=".env")

    parser = argparse.ArgumentParser(prog="sentinel_cli.py")
    parser.add_argument("command", nargs="?", help="Command to analyze (e.g. \"ls\")")
    parser.add_argument("--stdin", action="store_true", help="Read command from stdin")
    parser.add_argument("--agent-id", default="cli:local", help="Agent identifier")
    parser.add_argument("--timestamp", default="123", help="Client timestamp string to include in JSON body")
    parser.add_argument("--api-url", default=os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000/analyze"))
    parser.add_argument("--timeout", type=int, default=int(os.getenv("SENTINEL_HTTP_TIMEOUT", "10")))
    parser.add_argument("--json", action="store_true", help="Print raw JSON response")
    args = parser.parse_args()

    api_key = os.getenv("SENTINEL_API_KEY", "").strip()
    signing_secret = os.getenv("SENTINEL_SIGNING_SECRET", "").strip()

    if not api_key:
        print("ERROR: SENTINEL_API_KEY is missing in .env", file=sys.stderr)
        return 1
    if not signing_secret:
        print("ERROR: SENTINEL_SIGNING_SECRET is missing in .env", file=sys.stderr)
        return 1

    if args.stdin:
        cmd = (sys.stdin.read() or "").strip()
    else:
        cmd = (args.command or "").strip()

    if not cmd:
        print("ERROR: no command provided. Example: ./venv/bin/python sentinel_cli.py \"ls\"", file=sys.stderr)
        return 1

    ts_unix = str(int(time.time()))

    body = {
        "agent_id": args.agent_id,
        "command": cmd,
        "timestamp": args.timestamp,
    }

    signed_payload = {
        "agent_id": args.agent_id,
        "command": cmd,
        "timestamp": args.timestamp,
        "ts_unix": ts_unix,
    }

    sig = sign_payload(signing_secret, signed_payload)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Timestamp-Unix": ts_unix,
        "X-Signature": sig,
    }

    try:
        r = requests.post(args.api_url, json=body, headers=headers, timeout=args.timeout)
    except Exception as e:
        print(f"ERROR: cannot reach Sentinel API: {e}", file=sys.stderr)
        return 1

    # Try to parse JSON even on errors
    try:
        data = r.json()
    except Exception:
        print(f"ERROR: non-JSON response (HTTP {r.status_code}): {r.text}", file=sys.stderr)
        return 1

    # Print output
    if args.json:
        print(json.dumps({"_status_code": r.status_code, **data}, indent=2, sort_keys=True))
    else:
        if r.status_code != 200:
            detail = data.get("detail", data)
            print(f"HTTP {r.status_code}: {detail}")
            return 1

        decision = data.get("decision", "unknown")
        risk = data.get("risk", "unknown")
        reason = data.get("reason", "unknown")
        vt = data.get("vt", "")

        # Friendly format
        badge = "✅ APPROVED" if decision == "allow" else ("⛔ BLOCKED" if decision == "deny" else "⚠️ REVIEW")
        print(badge)
        print(f"Decision: {decision.upper()}")
        print(f"Risk: {risk.upper()}")
        print(f"Reason: {reason}")
        if vt:
            print(f"VT: {vt[:16]}…")

    return exit_code_for_decision(data.get("decision", ""))


if __name__ == "__main__":
    raise SystemExit(main())
