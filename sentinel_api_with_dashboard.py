import os
import json
import html
import time
import redis

from fastapi import Response, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from jinja2 import Environment, FileSystemLoader
from sentinel_api import app
from ops_digest import digest_action

templates = Environment(loader=FileSystemLoader("/app/templates"))

app.mount("/static", StaticFiles(directory="/app/static"), name="static")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

NEEDS_HUMAN_Q = "ops:actions:needs_human"
APPROVED_Q = "ops:actions:approved"
REJECTED_Q = "ops:actions:rejected"
EXECUTED_Q = "ops:actions:executed"
AGENTS_FILE = "/app/agents.json"

def now_ts() -> int:
    return int(time.time())


def qlen(key: str) -> int:
    try:
        return int(r.llen(key))
    except Exception:
        return -1


def lrange_safe(key: str, start: int, end: int):
    try:
        return r.lrange(key, start, end)
    except Exception:
        return []


def get_safe(key: str):
    try:
        return r.get(key)
    except Exception:
        return None


def set_safe(key: str, value: str, ex: int | None = None):
    if ex and ex > 0:
        r.setex(key, ex, value)
    else:
        r.set(key, value)


def record_key(action_id: str) -> str:
    return f"ops:actions:record:{action_id}"


def ttl_from_record(rec: dict, default_ttl: int = 900) -> int:
    try:
        exp = int(rec.get("expires_ts") or 0)
        if exp <= 0:
            return default_ttl
        ttl = exp - now_ts()
        return max(60, min(ttl, default_ttl))
    except Exception:
        return default_ttl


def jdump(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def jload(raw: str):
    return json.loads(raw)


def json_pretty(raw: str) -> str:
    if not raw:
        return ""
    try:
        obj = json.loads(raw)
        return html.escape(json.dumps(obj, indent=2, ensure_ascii=False))
    except Exception:
        return html.escape(raw)


def load_record(action_id: str) -> dict | None:
    raw = get_safe(record_key(action_id))
    if not raw:
        return None
    try:
        return jload(raw)
    except Exception:
        return None


def save_record(action_id: str, rec: dict):
    ttl = ttl_from_record(rec)
    set_safe(record_key(action_id), jdump(rec), ex=ttl)


def load_agents() -> dict:
    try:
        with open(AGENTS_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def live_agent_count() -> int:
    try:
        from agent_identity import list_agents
        return len(list_agents())
    except Exception:
        return len(load_agents())


def save_agents(agents: dict):
    with open(AGENTS_FILE, "w") as f:
        json.dump(agents, f, indent=2)


def render_cards(title: str, items: list[str]) -> str:
    if not items:
        return f"""
        <section class="panel">
          <h3>{html.escape(title)}</h3>
          <div class="empty">No items</div>
        </section>
        """
    blocks = []
    for item in items:
        blocks.append(f"<pre>{json_pretty(item)}</pre>")
    return f"""
    <section class="panel">
      <h3>{html.escape(title)}</h3>
      {''.join(blocks)}
    </section>
    """


def render_needs_human(items: list[str]) -> str:
    if not items:
        return """
        <section class="panel">
          <h3>Needs Human Approval (latest 5)</h3>
          <div class="empty">No items</div>
        </section>
        """

    cards = []
    for action_id in items:
        rec = load_record(action_id)
        if not rec:
            body = f"<div class='empty'>Missing record for <code>{html.escape(action_id)}</code></div>"
        else:
            action = rec.get("action") or {}
            status = html.escape(str(rec.get("status") or "unknown"))
            created = html.escape(str(rec.get("created_ts") or ""))
            reason = html.escape(str(action.get("reason") or ""))
            target = html.escape(str(action.get("target") or ""))
            action_type = html.escape(str(action.get("type") or ""))
            body = f"""
            <div class="meta"><b>Action ID:</b> <code>{html.escape(action_id)}</code></div>
            <div class="meta"><b>Status:</b> {status}</div>
            <div class="meta"><b>Type:</b> {action_type}</div>
            <div class="meta"><b>Target:</b> {target}</div>
            <div class="meta"><b>Reason:</b> {reason}</div>
            <div class="meta"><b>Created:</b> {created}</div>
            <pre>{html.escape(json.dumps(rec, indent=2, ensure_ascii=False))}</pre>
            <div class="actions">
              <a class="btn approve" href="/dashboard/approve?action_id={html.escape(action_id)}">Approve</a>
              <a class="btn reject" href="/dashboard/reject?action_id={html.escape(action_id)}">Reject</a>
            </div>
            """
        cards.append(f"<div class='item'>{body}</div>")

    return f"""
    <section class="panel">
      <h3>Needs Human Approval (latest 5)</h3>
      {''.join(cards)}
    </section>
    """


def summarize_event(raw: str) -> tuple[int, str]:
    try:
        obj = json.loads(raw)
    except Exception:
        return (0, html.escape(raw))

    ts = int(obj.get("ts") or 0)
    action_id = str(obj.get("action_id") or "unknown")

    if "execution" in obj:
        ex = obj.get("execution") or {}
        rec = obj.get("approved_msg") or {}
        action = rec.get("action") or {}
        target = action.get("target") or "?"
        status = "executed" if ex.get("ok") else "failed"
        return ts, f"{status} - {action_id} - target={target}"

    if obj.get("error") == "rejected":
        reason = obj.get("reason") or "rejected"
        return ts, f"rejected - {action_id} - reason={reason}"

    if "approved_msg" in obj:
        rec = obj.get("approved_msg") or {}
        action = rec.get("action") or {}
        target = action.get("target") or "?"
        return ts, f"approved - {action_id} - target={target}"

    return ts, f"event - {action_id}"


def render_timeline() -> str:
    events = []
    for raw in lrange_safe(REJECTED_Q, -10, -1):
        events.append(summarize_event(raw))
    for raw in lrange_safe(APPROVED_Q, -10, -1):
        events.append(summarize_event(raw))
    for raw in lrange_safe(EXECUTED_Q, -10, -1):
        events.append(summarize_event(raw))

    events.sort(key=lambda x: x[0], reverse=True)
    events = events[:12]

    if not events:
        return """
        <section class="panel">
          <h3>Recent Activity</h3>
          <div class="empty">No recent events</div>
        </section>
        """

    rows = []
    for ts, text in events:
        rows.append(f"<div class='timeline-row'><span class='ts'>{ts}</span><span>{html.escape(text)}</span></div>")

    return f"""
    <section class="panel">
      <h3>Recent Activity</h3>
      <div class="timeline">
        {''.join(rows)}
      </div>
    </section>
    """

from fastapi.responses import Response

@app.get("/", include_in_schema=False)
def homepage():
    html = templates.get_template("homepage.html").render()
    return Response(content=html, media_type="text/html")

def render_telemetry_panel() -> str:
    agents = load_agents()
    return f"""
    <section class="panel">
      <h3>Telemetry</h3>
      <table>
        <tbody>
          <tr><td>Registered agents</td><td>{len(agents)}</td></tr>
          <tr><td>Needs human</td><td>{qlen(NEEDS_HUMAN_Q)}</td></tr>
          <tr><td>Approved</td><td>{qlen(APPROVED_Q)}</td></tr>
          <tr><td>Rejected</td><td>{qlen(REJECTED_Q)}</td></tr>
          <tr><td>Executed</td><td>{qlen(EXECUTED_Q)}</td></tr>
        </tbody>
      </table>
    </section>
    """

def render_agents_panel() -> str:
    agents = load_agents()
    if not agents:
        return """
        <section class="panel">
          <h3>Agents</h3>
          <div class="empty">No agents found</div>
        </section>
        """

    rows = []
    for agent_id, meta in sorted(agents.items()):
        name = meta.get("name", "-")
        status = meta.get("status", "legacy")
        reputation = meta.get("reputation", "-")
        allowed = meta.get("allowed", "-")
        blocked = meta.get("blocked", "-")
        reviewed = meta.get("reviewed", "-")
        role = meta.get("role", "-")
        created_at = meta.get("created_at", "-")

        if status == "suspended":
            action_btn = f'<a class="btn approve" href="/dashboard/agent/activate?agent_id={html.escape(str(agent_id))}">Activate</a>'
        else:
            action_btn = f'<a class="btn reject" href="/dashboard/agent/suspend?agent_id={html.escape(str(agent_id))}">Suspend</a>'

        rows.append(f"""
        <tr>
          <td><code>{html.escape(str(agent_id))}</code></td>
          <td>{html.escape(str(name))}</td>
          <td><span class="pill {html.escape(str(status))}">{html.escape(str(status))}</span></td>
          <td>{html.escape(str(role))}</td>
          <td>{html.escape(str(reputation))}</td>
          <td>{html.escape(str(allowed))}</td>
          <td>{html.escape(str(blocked))}</td>
          <td>{html.escape(str(reviewed))}</td>
          <td>{html.escape(str(created_at))}</td>
          <td>{action_btn}</td>
        </tr>
        """)

    return f"""
    <section class="panel span-2">
      <h3>Agents</h3>
      <table>
        <thead>
          <tr>
            <th>Agent ID</th>
            <th>Name</th>
            <th>Status</th>
            <th>Role</th>
            <th>Reputation</th>
            <th>Allowed</th>
            <th>Blocked</th>
            <th>Reviewed</th>
            <th>Created</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </section>
    """

from fastapi.responses import Response

@app.get("/dashboard", include_in_schema=False)

def dashboard():
    needs_human_items = lrange_safe(NEEDS_HUMAN_Q, -5, -1)
    approved_items = lrange_safe(APPROVED_Q, -5, -1)
    rejected_items = lrange_safe(REJECTED_Q, -5, -1)
    executed_items = lrange_safe(EXECUTED_Q, -5, -1)
    approved_count = qlen(APPROVED_Q)
    rejected_count = qlen(REJECTED_Q)
    executed_count = qlen(EXECUTED_Q)
    needs_human_count = qlen(NEEDS_HUMAN_Q)

    html = templates.get_template("dashboard.html").render(
    telemetry_panel=render_telemetry_panel(),
    needs_human_panel=render_needs_human(needs_human_items),
    approved_panel=render_cards("Approved Actions (latest 5)", approved_items),
    rejected_panel=render_cards("Rejected Actions (latest 5)", rejected_items),
    executed_panel=render_cards("Executed Actions (latest 5)", executed_items),
    timeline_panel=render_timeline(),
    agents_panel=render_agents_panel(),
    agents_count=live_agent_count(),
    needs_human_count=needs_human_count,
    approved_count=approved_count,
    executed_count=executed_count,
    rejected_count=rejected_count,
    freeze_enabled=bool(getattr(__import__("sentinel_api"), "GLOBAL_FREEZE", False)),
    freeze_label="Freeze On" if bool(getattr(__import__("sentinel_api"), "GLOBAL_FREEZE", False)) else "Freeze Off",
    freeze_badge_class="bad" if bool(getattr(__import__("sentinel_api"), "GLOBAL_FREEZE", False)) else "good",
)

    return Response(content=html, media_type="text/html")
def render_public_homepage() -> str:
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel - The Firewall for AI Agents</title>

<style>
body{
  background:#050b1a;
  color:#e6ecff;
  font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
  margin:0;
  line-height:1.6;
}

.nav{
  position:sticky;
  top:0;
  z-index:50;
  background:rgba(5,11,26,.92);
  backdrop-filter:blur(10px);
  border-bottom:1px solid #1e2c5a;
}

.nav-inner{
  max-width:1100px;
  margin:auto;
  padding:16px 20px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:20px;
}

.brand{
  font-size:22px;
  font-weight:800;
  color:#fff;
}

.nav-links{
  display:flex;
  gap:18px;
  flex-wrap:wrap;
}

.nav-links a{
  color:#b9c6ea;
  text-decoration:none;
  font-size:14px;
}

.container{
  max-width:1100px;
  margin:auto;
  padding:70px 20px;
}

.hero{
  text-align:center;
  padding-top:80px;
  padding-bottom:40px;
}

.hero h1{
  font-size:56px;
  margin-bottom:18px;
}

.hero p{
  font-size:21px;
  opacity:.85;
  max-width:760px;
  margin:auto;
}

.buttons{
  margin-top:35px;
}

.btn{
  display:inline-block;
  padding:14px 28px;
  margin:8px;
  border-radius:12px;
  text-decoration:none;
  font-weight:700;
}

.btn-primary{
  background:#4f7cff;
  color:white;
}

.btn-outline{
  border:1px solid #4f7cff;
  color:#4f7cff;
}

.section{
  padding:40px 0;
}

.section h2{
  font-size:34px;
  margin-bottom:14px;
}

.section p{
  font-size:18px;
  opacity:.82;
  max-width:900px;
}

.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:24px;
  margin-top:30px;
}

.card{
  background:#0e1630;
  padding:28px;
  border-radius:14px;
  border:1px solid #1e2c5a;
}

.card h3{
  margin-top:0;
  margin-bottom:10px;
}

.arch-wrap{
  margin-top:30px;
}

.arch-grid{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:18px;
  align-items:center;
}

.arch-card{
  background:#0e1630;
  border:1px solid #1e2c5a;
  border-radius:16px;
  padding:24px;
  text-align:center;
  box-shadow:0 10px 30px rgba(0,0,0,.25);
  animation:floatCard 3.5s ease-in-out infinite;
}

.arch-card:nth-of-type(1){ animation-delay:.0s; }
.arch-card:nth-of-type(2){ animation-delay:.3s; }
.arch-card:nth-of-type(3){ animation-delay:.6s; }
.arch-card:nth-of-type(4){ animation-delay:.9s; }

.arch-title{
  font-size:18px;
  font-weight:700;
  margin-bottom:8px;
}

.arch-text{
  font-size:14px;
  opacity:.8;
}

.arch-arrow{
  text-align:center;
  font-size:26px;
  color:#4f7cff;
  animation:pulseArrow 1.8s ease-in-out infinite;
}

.dashboard-preview{
  margin-top:30px;
  border-radius:16px;
  overflow:hidden;
  border:1px solid #1e2c5a;
  box-shadow:0 20px 60px rgba(0,0,0,.35);
}

.cta{
  text-align:center;
  padding:60px 20px;
}

.cta h2{
  font-size:38px;
  margin-bottom:16px;
}

.footer{
  text-align:center;
  opacity:.6;
  padding:40px 0;
  font-size:14px;
  border-top:1px solid #1e2c5a;
  margin-top:30px;
}

@keyframes floatCard{
  0%{ transform:translateY(0px); }
  50%{ transform:translateY(-6px); }
  100%{ transform:translateY(0px); }
}

@keyframes pulseArrow{
  0%{ opacity:.45; transform:scale(1); }
  50%{ opacity:1; transform:scale(1.08); }
  100%{ opacity:.45; transform:scale(1); }
}

@media(max-width:900px){
  .hero h1{font-size:40px;}
  .hero p{font-size:18px;}
  .arch-grid{grid-template-columns:1fr;}
  .arch-arrow{transform:rotate(90deg);}
  .nav-inner{flex-direction:column; align-items:flex-start;}
}
</style>
</head>
<body>

<div class="nav">
  <div class="nav-inner">
    <div class="brand">Sentinel</div>
    <div class="nav-links">
      <a href="#product">Product</a>
      <a href="#capabilities">Capabilities</a>
      <a href="#architecture">Architecture</a>
      <a href="#dashboard">Dashboard</a>
      <a href="/dashboard">Ops Dashboard</a>
    </div>
  </div>
</div>

<div class="container hero" id="product">
  <h1>The Firewall for AI Agents</h1>
  <p>
    Sentinel is a security control layer that evaluates, approves, and monitors
    AI agent actions before they execute against infrastructure.
  </p>

  <div class="buttons">
    <a class="btn btn-primary" href="/dashboard">View Dashboard</a>
    <a class="btn btn-outline" href="mailto:sentinel.labs.ai@gmail.com">Request Access</a>
  </div>
</div>

<div class="container section">
  <h2>Why Sentinel Exists</h2>
  <p>
    AI agents can now run commands, call APIs, modify infrastructure, and interact
    with production systems. Without guardrails, a single compromised agent or prompt
    injection can cause serious damage. Sentinel introduces a security layer between
    AI agents and the systems they control.
  </p>
</div>

<div class="container section" id="capabilities">
  <h2>Core Capabilities</h2>
  <div class="grid">
    <div class="card">
      <h3>Agent Identity</h3>
      <p>Each AI agent is registered and authenticated before actions are accepted.</p>
    </div>
    <div class="card">
      <h3>Policy Enforcement</h3>
      <p>Commands are checked against security rules before execution.</p>
    </div>
    <div class="card">
      <h3>Risk Scoring</h3>
      <p>Every action is evaluated for impact and operational risk.</p>
    </div>
    <div class="card">
      <h3>Human Approval</h3>
      <p>Sensitive operations require explicit human authorization.</p>
    </div>
    <div class="card">
      <h3>Execution Control</h3>
      <p>Only approved actions move forward through controlled workers.</p>
    </div>
    <div class="card">
      <h3>Audit Trail</h3>
      <p>Every action is logged with timestamps, signatures, and decisions.</p>
    </div>
  </div>
</div>

<div class="container section" id="architecture">
  <h2>Security Architecture</h2>
  <p>
    Sentinel sits between AI agents and infrastructure, enforcing identity,
    policy, approval, and secure execution.
  </p>

  <div class="arch-wrap">
    <div class="arch-grid">
      <div class="arch-card">
        <div class="arch-title">AI Agent</div>
        <div class="arch-text">Autonomous system proposing an action.</div>
      </div>

      <div class="arch-arrow">→</div>

      <div class="arch-card">
        <div class="arch-title">Sentinel Policy Engine</div>
        <div class="arch-text">Evaluates identity, risk, and policy rules.</div>
      </div>

      <div class="arch-arrow">→</div>

      <div class="arch-card">
        <div class="arch-title">Human Approval</div>
        <div class="arch-text">Sensitive operations require explicit review.</div>
      </div>

      <div class="arch-arrow">→</div>

      <div class="arch-card">
        <div class="arch-title">Secure Execution</div>
        <div class="arch-text">Only approved actions reach infrastructure.</div>
      </div>
    </div>
  </div>
</div>

<div class="container section" id="dashboard">
  <h2>Live Security Operations</h2>
  <p>
    Sentinel provides a real-time dashboard where operators can monitor activity,
    approve or reject actions, suspend agents, and inspect security decisions.
  </p>

  <div class="dashboard-preview">
    <img src="/static/dashboard.png" alt="Sentinel Dashboard" style="width:100%;display:block;">
  </div>
</div>

<div class="container cta">
  <h2>Secure AI agents before they reach production.</h2>
  <div class="buttons">
    <a class="btn btn-primary" href="/dashboard">Explore Sentinel</a>
    <a class="btn btn-outline" href="mailto:sentinel.labs.ai@gmail.com">Talk to Founder</a>
  </div>
</div>

<div class="container footer">
  Sentinel Security Control Architecture - © 2026
</div>

</body>
</html>
"""

@app.get("/", include_in_schema=False)
def homepage():
    return Response(content=render_public_homepage(), media_type="text/html")
