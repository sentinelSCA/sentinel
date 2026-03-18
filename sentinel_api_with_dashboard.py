import os
import json
import html
import time
import redis

from fastapi import Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from sentinel_api import app, set_global_freeze, get_global_freeze
from sentinel_ops import (
    load_action,
    approve_action,
    reject_action,
    dashboard_counts,
    dashboard_lists,
)

templates = Jinja2Templates(directory="/app/templates")
app.mount("/static", StaticFiles(directory="/app/static"), name="static")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

AGENTS_FILE = "/app/agents.json"


def now_ts() -> int:
    return int(time.time())


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


def load_record(action_id: str) -> dict | None:
    return load_action(action_id)


def fmt_ts(ts) -> str:
    try:
        return str(int(ts))
    except Exception:
        return "—"


def action_summary(rec: dict) -> dict:
    action = rec.get("action") or {}
    return {
        "action_id": str(rec.get("action_id") or "—"),
        "agent_id": str(rec.get("agent_id") or "—"),
        "status": str(rec.get("status") or rec.get("decision") or "unknown"),
        "type": str(action.get("type") or "—"),
        "target": str(action.get("target") or "—"),
        "reason": str(rec.get("reason") or action.get("reason") or "—"),
        "created_ts": fmt_ts(
            rec.get("executed_ts")
            or rec.get("approved_ts")
            or rec.get("rejected_ts")
            or rec.get("created_ts")
            or rec.get("ts")
        ),
    }


def compact_card(summary: dict, tone: str = "") -> str:
    tone_class = f" item-{tone}" if tone else ""
    return f"""
    <div class="item{tone_class}">
      <div class="item-title">{html.escape(summary["status"].title())} · <code>{html.escape(summary["action_id"])}</code></div>
      <div class="meta-grid">
        <div class="meta"><span>Agent</span><b>{html.escape(summary["agent_id"])}</b></div>
        <div class="meta"><span>Type</span><b>{html.escape(summary["type"])}</b></div>
        <div class="meta"><span>Target</span><b>{html.escape(summary["target"])}</b></div>
        <div class="meta"><span>Time</span><b>{html.escape(summary["created_ts"])}</b></div>
      </div>
      <div class="meta reason-line"><span>Reason</span><b>{html.escape(summary["reason"])}</b></div>
    </div>
    """


def render_history_cards(title: str, items: list[str], tone: str, empty_text: str) -> str:
    if not items:
        return f"""
        <section class="panel">
          <h3>{html.escape(title)}</h3>
          <div class="empty">{html.escape(empty_text)}</div>
        </section>
        """

    blocks = []
    for raw in reversed(items):
        try:
            obj = json.loads(raw)
        except Exception:
            continue

        if "approved_msg" in obj and isinstance(obj.get("approved_msg"), dict):
            rec = obj["approved_msg"]
            rec.setdefault("action_id", obj.get("action_id"))
            if "execution" in obj and isinstance(obj["execution"], dict):
                rec["execution"] = obj["execution"]
                rec["status"] = "executed" if obj["execution"].get("ok") else "failed"
                rec["executed_ts"] = obj["execution"].get("executed_ts") or obj.get("ts")
        else:
            rec = obj

        summary = action_summary(rec)
        blocks.append(compact_card(summary, tone=tone))

    return f"""
    <section class="panel">
      <h3>{html.escape(title)}</h3>
      {''.join(blocks) if blocks else f'<div class="empty">{html.escape(empty_text)}</div>'}
    </section>
    """


def render_needs_human(items: list[str]) -> str:
    if not items:
        return """
        <section class="panel">
          <h3>Needs Human Approval Queue</h3>
          <div class="empty">No actions awaiting review</div>
        </section>
        """

    ranked = []
    missing = []

    for action_id in items:
        rec = load_record(action_id)
        if not rec:
            missing.append(action_id)
            continue

        try:
            risk_score = float(rec.get("risk_score") or 0.0)
        except Exception:
            risk_score = 0.0

        try:
            created_ts = int(rec.get("created_ts") or 0)
        except Exception:
            created_ts = 0

        ranked.append((risk_score, created_ts, action_id, rec))

    ranked.sort(key=lambda x: (x[0], x[1]), reverse=True)

    cards = []
    for risk_score, created_ts, action_id, rec in ranked[:5]:
        action = rec.get("action") or {}
        status = html.escape(str(rec.get("status") or "unknown"))
        created = html.escape(fmt_ts(rec.get("created_ts")))
        reason = html.escape(str(rec.get("reason") or action.get("reason") or "—"))
        target = html.escape(str(action.get("target") or "—"))
        action_type = html.escape(str(action.get("type") or "—"))
        agent_id = html.escape(str(rec.get("agent_id") or "—"))
        risk_label = html.escape(str(rec.get("risk") or "unknown"))
        score_label = html.escape(f"{risk_score:.2f}")

        body = f"""
        <div class="item item-review">
          <div class="item-title">Pending Review · <code>{html.escape(action_id)}</code></div>
          <div class="meta-grid">
            <div class="meta"><span>Agent</span><b>{agent_id}</b></div>
            <div class="meta"><span>Status</span><b>{status}</b></div>
            <div class="meta"><span>Type</span><b>{action_type}</b></div>
            <div class="meta"><span>Target</span><b>{target}</b></div>
            <div class="meta"><span>Risk</span><b>{risk_label}</b></div>
            <div class="meta"><span>Risk Score</span><b>{score_label}</b></div>
          </div>
          <div class="meta reason-line"><span>Reason</span><b>{reason}</b></div>
          <div class="meta"><span>Created</span><b>{created}</b></div>
          <div class="actions">
            <a class="btn approve" href="/dashboard/approve?action_id={html.escape(action_id)}">Approve</a>
            <a class="btn reject" href="/dashboard/reject?action_id={html.escape(action_id)}">Reject</a>
          </div>
        </div>
        """
        cards.append(body)

    hidden_count = max(0, len(ranked) - 5)
    hidden_note = ""
    if hidden_count:
        hidden_note = f'<div class="empty" style="margin-top:12px;">Showing top 5 priority items · {hidden_count} more pending</div>'

    for action_id in missing[:2]:
        cards.append(f"<div class='empty'>Missing record for <code>{html.escape(action_id)}</code></div>")

    return f"""
    <section class="panel">
      <h3>Needs Human Approval Queue</h3>
      {''.join(cards)}
      {hidden_note}
    </section>
    """


def summarize_event(raw: str) -> tuple[int, str]:
    try:
        obj = json.loads(raw)
    except Exception:
        return (0, "Unknown event")

    if "approved_msg" in obj and isinstance(obj.get("approved_msg"), dict):
        rec = obj["approved_msg"]
        action = rec.get("action") or {}
        action_id = str(obj.get("action_id") or rec.get("action_id") or "unknown")
        target = str(action.get("target") or "—")
        ts = int(obj.get("ts") or rec.get("created_ts") or 0)
        if "execution" in obj:
            return ts, f"Executed · {action_id} · {target}"
        return ts, f"Approved · {action_id} · {target}"

    action = obj.get("action") or {}
    action_id = str(obj.get("action_id") or "unknown")
    target = str(action.get("target") or obj.get("target") or "—")
    ts = int(
        obj.get("executed_ts")
        or obj.get("approved_ts")
        or obj.get("rejected_ts")
        or obj.get("created_ts")
        or obj.get("ts")
        or 0
    )

    if obj.get("status") == "rejected" or obj.get("decision") == "rejected" or obj.get("error") == "rejected":
        return ts, f"Rejected · {action_id} · {target}"
    if obj.get("status") == "approved" or obj.get("decision") == "approved":
        return ts, f"Approved · {action_id} · {target}"
    if obj.get("status") == "executed":
        return ts, f"Executed · {action_id} · {target}"

    return ts, f"Event · {action_id}"


def render_timeline() -> str:
    counts = dashboard_counts()
    lists = dashboard_lists()
    events = []

    for action_id in lists["needs_human"]:
        rec = load_record(action_id)
        if rec:
            ts = int(rec.get("created_ts") or now_ts())
            action = rec.get("action") or {}
            target = str(action.get("target") or "—")
            events.append((ts, f"Pending Review · {action_id} · {target}"))

    for raw in lists["approved"]:
        events.append(summarize_event(raw))
    for raw in lists["rejected"]:
        events.append(summarize_event(raw))
    for raw in lists["executed"]:
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
        rows.append(
            f"<div class='timeline-row'>"
            f"<div class='timeline-ts'>{html.escape(fmt_ts(ts))}</div>"
            f"<div class='timeline-text'>{html.escape(text)}</div>"
            f"</div>"
        )

    return f"""
    <section class="panel">
      <h3>Recent Activity</h3>
      <div class="timeline">
        {''.join(rows)}
      </div>
    </section>
    """


def render_agents_panel() -> str:
    agents = load_agents()
    if not agents:
        return """
        <section class="panel span-2">
          <h3>Agents</h3>
          <div class="empty">No agents found</div>
        </section>
        """

    rows = []
    for agent_id, meta in sorted(agents.items()):
        name = meta.get("name", "-")
        status = meta.get("status", "legacy")
        reputation = meta.get("reputation", "-")
        role = meta.get("role", "-")
        created_at = meta.get("created_at", "-")

        rows.append(f"""
        <tr>
          <td><code>{html.escape(str(agent_id))}</code></td>
          <td>{html.escape(str(name))}</td>
          <td><span class="pill {html.escape(str(status))}">{html.escape(str(status))}</span></td>
          <td>{html.escape(str(role))}</td>
          <td>{html.escape(str(reputation))}</td>
          <td>{html.escape(str(created_at))}</td>
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
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </section>
    """


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
def homepage(request: Request):
    return templates.TemplateResponse("homepage.html", {"request": request})



@app.get("/dashboard/data", include_in_schema=False)
def dashboard_data():
    counts = dashboard_counts()
    lists = dashboard_lists()

    return {
        "counts": {
            "needs_human": counts["needs_human"],
            "approved": counts["approved"],
            "rejected": counts["rejected"],
            "executed": counts["executed"],
            "agents": live_agent_count(),
            "freeze": bool(get_global_freeze()),
        },
        "panels": {
            "needs_human": render_needs_human(lists["needs_human"]),
            "timeline": render_timeline(),
            "approved": render_history_cards("Recent Approved Actions", lists["approved"], "approved", "No approved actions yet"),
            "rejected": render_history_cards("Recent Rejected Actions", lists["rejected"], "rejected", "No rejected actions yet"),
            "executed": render_history_cards("Recent Executed Actions", lists["executed"], "executed", "No executed actions yet"),
        }
    }

@app.get("/dashboard", include_in_schema=False)
def dashboard():
    counts = dashboard_counts()
    lists = dashboard_lists()

    html_doc = templates.get_template("dashboard.html").render(
        request=None,
        needs_human_panel=render_needs_human(lists["needs_human"]),
        approved_panel=render_history_cards("Recent Approved Actions", lists["approved"], "approved", "No approved actions yet"),
        rejected_panel=render_history_cards("Recent Rejected Actions", lists["rejected"], "rejected", "No rejected actions yet"),
        executed_panel=render_history_cards("Recent Executed Actions", lists["executed"], "executed", "No executed actions yet"),
        timeline_panel=render_timeline(),
        agents_panel=render_agents_panel(),
        agents_count=live_agent_count(),
        needs_human_count=counts["needs_human"],
        approved_count=counts["approved"],
        executed_count=counts["executed"],
        rejected_count=counts["rejected"],
        freeze_enabled=get_global_freeze(),
        freeze_label="Freeze Off" if not get_global_freeze() else "Freeze On",
        freeze_badge_class="good" if not get_global_freeze() else "bad",
    )
    return Response(content=html_doc, media_type="text/html")


@app.get("/dashboard/freeze/on", include_in_schema=False)
def dashboard_freeze_on():
    set_global_freeze(True)
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard/freeze/off", include_in_schema=False)
def dashboard_freeze_off():
    set_global_freeze(False)
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard/reject")
def dashboard_reject(action_id: str):
    rec = reject_action(action_id)
    if not rec:
        return {"detail": "Record not found"}
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/dashboard/approve")
def dashboard_approve(action_id: str):
    rec = approve_action(action_id)
    if not rec:
        return {"detail": "Record not found"}
    return RedirectResponse(url="/dashboard", status_code=302)
