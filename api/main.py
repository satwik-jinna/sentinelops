from __future__ import annotations

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

from agents.graph import sentinelops_graph

load_dotenv()

app = FastAPI(
    title="SentinelOps",
    description="Autonomous security operations agent platform.",
    version="0.1.0",
)


class AlertIn(BaseModel):
    source: str
    raw_alert: str


class AlertOut(BaseModel):
    alert_id: str
    severity: str
    alert_type: str
    action: str
    confidence: float
    rationale: str
    recommended_playbook: str
    trace: list[str]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/alerts", response_model=AlertOut)
def process_alert(alert: AlertIn) -> AlertOut:
    result = sentinelops_graph.invoke(
        {"source": alert.source, "raw_alert": alert.raw_alert}
    )
    return AlertOut(
        alert_id=result["alert_id"],
        severity=result["severity"],
        alert_type=result["alert_type"],
        action=result["action"],
        confidence=result["confidence"],
        rationale=result["rationale"],
        recommended_playbook=result["recommended_playbook"],
        trace=result["trace"],
    )
