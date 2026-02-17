import os
import time
import json
import hmac
import hashlib
import requests
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# Load .env from project folder (safe + consistent)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

API_URL = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000/analyze")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

API_KEY = os.getenv("SENTINEL_API_KEY", "")
SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "")
TIMEOUT_SECS = int(os.getenv("SENTINEL_HTTP_TIMEOUT", "10"))

def _sign(payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(SIGNING_SECRET.encode(), msg, hashlib.sha256).hexdigest()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ Sentinel SCA Bot Online\n\nSend a command and I’ll evaluate it."
    )

async def analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not text:
        return

    agent_id = f"tg:{update.effective_chat.id}"
    ts_unix = str(int(time.time()))
    body = {"agent_id": agent_id, "command": text, "timestamp": ts_unix}

    headers = {"Content-Type": "application/json"}

    # API key protection (if enabled)
    if API_KEY:
        headers["X-API-Key"] = API_KEY

    # Signature protection (if enabled)
    if SIGNING_SECRET:
        signed_payload = {
            "agent_id": body["agent_id"],
            "command": body["command"],
            "timestamp": body["timestamp"],
            "ts_unix": ts_unix,
        }
        headers["X-Timestamp-Unix"] = ts_unix
        headers["X-Signature"] = _sign(signed_payload)

    try:
        r = requests.post(API_URL, json=body, headers=headers, timeout=TIMEOUT_SECS)
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    except Exception as e:
        await update.message.reply_text(f"❌ API error: {e}")
        return

    # Handle common HTTP errors cleanly
    if r.status_code == 401:
        await update.message.reply_text("❌ Unauthorized (401). Check API key/signature config.")
        return
    if r.status_code == 409:
        await update.message.reply_text("⚠️ Replay detected (409). Try again in a second.")
        return
    if r.status_code == 429:
        await update.message.reply_text("⏳ Rate limited (429). Slow down a bit.")
        return
    if r.status_code != 200:
        await update.message.reply_text(f"❌ API error ({r.status_code}): {data}")
        return

    decision = data.get("decision", "UNKNOWN").upper()
    risk = data.get("risk", "UNKNOWN").upper()
    reason = data.get("reason", "Unknown")
    vt = data.get("vt", "")

    badge = "✅ APPROVED" if decision == "ALLOW" else ("⛔ BLOCKED" if decision == "DENY" else "⚠️ REVIEW")

    msg = (
        f"{badge}\n"
        f"Decision: {decision}\n"
        f"Risk: {risk}\n"
        f"Reason: {reason}\n"
    )
    if vt:
        msg += f"VT: {vt[:16]}…\n"

    msg += "\n🛡️ Sentinel SCA Bot Online"
    await update.message.reply_text(msg)

def main():
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN missing in .env")

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze))

    print("✅ Sentinel Telegram bot running...")
    app.run_polling()

if __name__ == "__main__":
    main()
