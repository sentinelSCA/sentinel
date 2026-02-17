<p align="center">
  <img src="logo.png" width="220" alt="SCA Sentinel Compliance Agent logo">
</p>

# SCA — Sentinel Compliance Agent

**Signed-command security gateway for AI agents and automation systems.**

SCA evaluates, signs, and enforces policies on commands **before execution**, preventing unsafe or malicious actions.

Built on the **Sentinel Security Engine**.

---

## 🔐 Core Capabilities

- HMAC-SHA256 request signing
- Replay protection (nonce + timestamp)
- Per-agent rate limiting
- Agent reputation scoring
- Deterministic policy enforcement
- Signed CLI client
- Optional Telegram bot integration
- Structured logging
- Zero-trust execution model

---

## 🚀 Quick Start

### 1️⃣ Install

```bash
git clone https://github.com/yourname/sca-sentinel.git
cd sca-sentinel

python -m venv venv
./venv/bin/pip install -e .
```

---

### 2️⃣ Start API Server

```bash
./venv/bin/uvicorn sentinel_api:app --host 127.0.0.1 --port 8000
```

Server runs locally at:

```
http://127.0.0.1:8000
```

---

### 3️⃣ Run CLI

Allow example:

```bash
./venv/bin/sentinel "ls"
```

Blocked example:

```bash
./venv/bin/sentinel "rm -rf /"
```

---

### 4️⃣ (Optional) Telegram Bot

```bash
./venv/bin/python sentinel_telegram.py
```

Use Telegram as a remote signed command interface.

---

## 🧪 Direct API Testing

```bash
tools/test_request.sh ls a
tools/test_request.sh "rm -rf /" a
```

---

## 📤 Exit Codes

| Code | Meaning |
|--------|-----------|
| 0 | Allow |
| 2 | Deny |
| 3 | Review / Warning |
| 1 | Client or runtime error |

---

## ⚠️ Common Errors

| Code | Cause |
|--------|------------------------------|
| 401 | Missing or invalid signature |
| 409 | Replay detected |
| 429 | Rate limit exceeded |

---

## 🛡 Security Model

Sentinel follows a **defense-in-depth architecture**:

- Constant-time signature verification (`compare_digest`)
- Canonical JSON signing (sorted keys, compact separators)
- Timestamp validation window
- Nonce replay prevention
- Per-agent quotas
- Reputation scoring
- Policy-based deny rules
- Structured audit logs

### Enforcement Flow

```
signed → verified → rate-checked → reputation-checked → policy-checked → executed
```

Nothing bypasses Sentinel.

---

## ⚙ Environment Variables

```bash
SENTINEL_API_KEY=sentinel-local-111111
SENTINEL_SIGNING_SECRET=change-me
SENTINEL_RATE_LIMIT_MAX=30
SENTINEL_RATE_LIMIT_WINDOW_SEC=60
```

---

## 📂 Project Structure

```
sentinel_api.py         FastAPI server
sentinel_cli_pkg/       Signed CLI client package
sentinel_guard.py       Core evaluation logic
sentinel_telegram.py    Telegram bot integration
tools/                  Test utilities
logs/                   Runtime logs
docs/                   Architecture & roadmap
```

---

## 🎯 Use Cases

- AI agent command gating
- Secure automation systems
- CLI protection
- Telegram remote execution with trust
- Zero-trust command approval
- Local or self-hosted security gateway

---

## 📜 License

Internal / Experimental

---

## 🧠 Philosophy

Security first.  
Trust nothing.  
Verify everything.

All commands must be signed and validated.

Sentinel is the gatekeeper.
