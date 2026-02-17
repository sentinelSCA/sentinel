import os
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

SENTINEL_URL = os.getenv("SENTINEL_URL", "http://127.0.0.1:8000/analyze")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ALLOWED_CHAT = os.getenv("TELEGRAM_ALLOWED_CHAT", "").strip()

def allowed(update: Update) -> bool:
    if not ALLOWED_CHAT:
        return True
    return str(update.effective_chat.id) == ALLOWED_CHAT

def call_sentinel(command: str) -> dict:
    import time, json, hmac, hashlib

    api_key = os.getenv("SENTINEL_API_KEY", "")
    secret = os.getenv("SENTINEL_SIGNING_SECRET", "")
    if not api_key or not secret:
        raise RuntimeError("Missing SENTINEL_API_KEY or SENTINEL_SIGNING_SECRET in env")

    ts = str(int(time.time()))  # timestamp MUST be string
    agent_id = "telegram"

    body_obj = {
        "agent_id": agent_id,
        "command": command,
        "timestamp": ts,
        "reputation": 0,
    }

    signed_payload = {
        "agent_id": agent_id,
        "command": command,
        "timestamp": ts,
        "ts_unix": ts,
    }

    msg = json.dumps(signed_payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Timestamp-Unix": ts,
        "X-Signature": sig,
    }

    r = requests.post(SENTINEL_URL, json=body_obj, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()

def fmt(d: dict) -> str:
    decision = d.get("decision", "UNKNOWN")
    risk = d.get("risk", "UNKNOWN")
    reason = d.get("reason", "")
    vt = d.get("vt") or d.get("variable_timestamp") or ""
    policy = d.get("policy_version", "")
    sig = d.get("signature", "")

    out = [
        "🛡️ Sentinel SCA",
        f"Decision: {decision}",
        f"Risk: {risk}",
    ]

    if reason:
        out.append(f"Reason: {reason}")

    if policy:
        out.append(f"Policy: {policy}")

    if vt:
        out.append(f"VT: {vt}")

    if sig:
        out.append(f"Signature: {sig}")

    return "\n".join(out)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return

    cmd = update.message.text
    try:
        result = call_sentinel(cmd)
        await update.message.reply_text(fmt(result))
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")


def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("🤖 Telegram bot running...")
    app.run_polling()


if __name__ == "__main__":
    main()
