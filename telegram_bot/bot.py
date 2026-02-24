import os
import json
import time
import hmac
import hashlib
import logging
from datetime import datetime, timezone

import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# Your project helper (Ed25519 signing)
# Must exist in /app/agent_identity.py with function sign_payload(priv_b64, payload_dict) -> str
from agent_identity import sign_payload

# ----------------------------
# Config
# ----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sentinel-telegram-bot")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_CHAT = os.getenv("TELEGRAM_ADMIN_CHAT", "").strip()

# IMPORTANT: inside docker, never use 127.0.0.1 for sentinel-api
SENTINEL_URL = os.getenv("SENTINEL_URL", "http://sentinel-api:8001/analyze").strip()
API_BASE_URL = os.getenv("API_BASE_URL", "http://sentinel-api:8001").strip()

API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()
SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "").strip()

AGENT_ID = os.getenv("AGENT_ID", "").strip()
AGENT_PRIV_B64 = os.getenv("AGENT_PRIV_B64", "").strip()

HTTP_TIMEOUT = int(os.getenv("SENTINEL_HTTP_TIMEOUT", "10"))

if not BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN in env")
if not API_KEY:
    raise RuntimeError("Missing SENTINEL_API_KEY in env")
if not SIGNING_SECRET:
    raise RuntimeError("Missing SENTINEL_SIGNING_SECRET in env")
if not AGENT_ID or not AGENT_PRIV_B64:
    raise RuntimeError("Missing AGENT_ID or AGENT_PRIV_B64 in env")


def _hmac_signature(agent_id: str, command: str, ts_iso: str, ts_unix: str) -> str:
    # Must match server-side canonicalization
    body = json.dumps(
        {"agent_id": agent_id, "command": command, "timestamp": ts_iso, "ts_unix": ts_unix},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(SIGNING_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()


def sentinel_analyze(command: str) -> dict:
    ts_iso = datetime.now(timezone.utc).isoformat()
    ts_unix = str(int(time.time()))

    payload = {
        "agent_id": AGENT_ID,
        "command": command,
        "timestamp": ts_iso,
        "reputation": 0.0,
    }

    x_sig = _hmac_signature(AGENT_ID, command, ts_iso, ts_unix)

    agent_sig_payload = {
        "agent_id": AGENT_ID,
        "command": command,
        "timestamp": ts_iso,
        "ts_unix": ts_unix,
    }
    agent_sig = sign_payload(AGENT_PRIV_B64, agent_sig_payload)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Timestamp-Unix": ts_unix,
        "X-Signature": x_sig,
        "X-Agent-Signature": agent_sig,
    }

    r = requests.post(SENTINEL_URL, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
    # Helpful error message
    if r.status_code >= 400:
        raise RuntimeError(f"Sentinel HTTP {r.status_code}: {r.text}")
    return r.json()


def api_health() -> dict:
    r = requests.get(f"{API_BASE_URL}/health", timeout=5)
    if r.status_code >= 400:
        raise RuntimeError(f"Health HTTP {r.status_code}: {r.text}")
    return r.json()


def _is_admin(update: Update) -> bool:
    if not ADMIN_CHAT:
        return True  # if not set, allow anyone
    return str(update.effective_chat.id) == str(ADMIN_CHAT)


# ----------------------------
# Telegram handlers
# ----------------------------
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Sentinel bot online.\n"
        "Send any text to analyze it.\n"
        "Commands: /health /whoami"
    )


async def cmd_whoami(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"chat_id={update.effective_chat.id}\n"
        f"SENTINEL_URL={SENTINEL_URL}\n"
        f"API_BASE_URL={API_BASE_URL}"
    )


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        h = api_health()
        await update.message.reply_text(f"health: {json.dumps(h)}")
    except Exception as e:
        await update.message.reply_text(f"health error: {e}")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return

    if not _is_admin(update):
        await update.message.reply_text("Not authorized.")
        return

    text = update.message.text.strip()

    # Ignore telegram commands here; they are handled by CommandHandlers
    if text.startswith("/"):
        return

    try:
        result = sentinel_analyze(text)
        decision = result.get("decision")
        risk = result.get("risk")
        reason = result.get("reason")
        score = result.get("risk_score")

        await update.message.reply_text(
            f"decision={decision} risk={risk} score={score}\nreason={reason}"
        )
    except Exception as e:
        # This is where yesterday’s 127.0.0.1 issue shows up clearly
        await update.message.reply_text(f"analyze error: {e}")


def main():
    log.info("telegram bot starting…")
    log.info("SENTINEL_URL=%s", SENTINEL_URL)
    log.info("API_BASE_URL=%s", API_BASE_URL)

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("health", cmd_health))
    app.add_handler(CommandHandler("whoami", cmd_whoami))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    app.run_polling(close_loop=False)


if __name__ == "__main__":
    main()
