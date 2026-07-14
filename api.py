"""
AI SOC Copilot — REST API

A FastAPI backend that exposes the same SQLite incident database used by
the Streamlit UI (app.py), so incidents can be listed, inspected, updated,
and deleted programmatically — separately from the dashboard.

Run this alongside the Streamlit app (two separate processes):

    uvicorn api:app --reload --port 8000

Then browse the interactive docs at:

    http://127.0.0.1:8000/docs

Note: this API currently has no authentication. It reads/writes the same
data/soc_incidents.db file as the Streamlit app, so anyone who can reach
this port can view and modify incidents. Fine for local/demo use; add an
API key or token check before exposing this publicly.
"""

from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from utils.incident_db import (
    init_db,
    get_all_incidents,
    get_incident_by_id,
    update_incident_status,
    delete_incident,
    get_incident_stats,
)

VALID_STATUSES = ["Open", "Investigating", "Resolved"]

app = FastAPI(
    title="AI SOC Copilot API",
    description=(
        "REST API for managing security incidents detected by the "
        "AI SOC Copilot's Isolation Forest model and MITRE ATT&CK mapping."
    ),
    version="1.0.0",
)

init_db()




class Incident(BaseModel):
    id: int
    detected_at: str
    destination_port: Optional[int] = None
    flow_duration: Optional[float] = None
    prediction: Optional[str] = None
    risk: Optional[str] = None
    attack_type: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None
    technique_id: Optional[str] = None
    description: Optional[str] = None
    mitigation: Optional[str] = None
    gemini_explanation: Optional[str] = None
    status: str


class IncidentStats(BaseModel):
    total: int
    open: int
    investigating: int
    resolved: int
    high_risk: int


class StatusUpdateRequest(BaseModel):
    status: str


class DeleteResponse(BaseModel):
    message: str




@app.get("/health")
def health_check():
    """
    Simple liveness check for uptime monitoring / load balancers.
    """
    return {"status": "ok"}


@app.get("/incidents", response_model=List[Incident])
def list_incidents(status: Optional[str] = None, risk: Optional[str] = None):
    """
    Lists stored incidents, most recent first.

    Optional query params:
      - status: "Open", "Investigating", or "Resolved"
      - risk: e.g. "🔴 High" or "🟢 Low"
    """
    return get_all_incidents(status=status, risk=risk)


@app.get("/incidents/stats", response_model=IncidentStats)
def incident_stats():
    """
    Returns summary counts (total, by status, high risk) for dashboards
    or monitoring integrations.
    """
    return get_incident_stats()


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: int):
    """
    Fetches a single incident by id.
    """
    incident = get_incident_by_id(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404, detail=f"Incident {incident_id} not found"
        )

    return incident


@app.patch("/incidents/{incident_id}/status", response_model=Incident)
def update_status(incident_id: int, payload: StatusUpdateRequest):
    """
    Updates the workflow status of an incident (Open / Investigating /
    Resolved).
    """
    if get_incident_by_id(incident_id) is None:
        raise HTTPException(
            status_code=404, detail=f"Incident {incident_id} not found"
        )

    if payload.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {VALID_STATUSES}",
        )

    update_incident_status(incident_id, payload.status)

    return get_incident_by_id(incident_id)


@app.delete("/incidents/{incident_id}", response_model=DeleteResponse)
def remove_incident(incident_id: int):
    """
    Permanently deletes an incident.
    """
    if get_incident_by_id(incident_id) is None:
        raise HTTPException(
            status_code=404, detail=f"Incident {incident_id} not found"
        )

    delete_incident(incident_id)

    return {"message": f"Incident {incident_id} deleted"}