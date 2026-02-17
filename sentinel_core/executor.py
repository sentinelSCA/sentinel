from fastapi import FastAPI
from pydantic import BaseModel

from sentinel_rules.policy_v2 import evaluate_command_v2
from sentinel_core.utils import variable_timestamp
from sentinel_core.reputation import update_reputation
from sentinel_core.executor import execute_action


app = FastAPI(title="Sentinel Compliance Agent API")


class CommandRequest(BaseModel):
    command: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: CommandRequest):
    cmd = req.command

    decision, risk, reason = evaluate_command_v2(cmd)

    vt = variable_timestamp(cmd)

    update_reputation(decision)

    execution = execute_action(cmd, decision)

    return {
        "decision": decision,
        "risk": risk,
        "reason": reason,
        "variable_timestamp": vt,
        "execution": execution
    }
