"""Simulation / event / alert / incident schemas."""
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel, Paginated


class SimulationCreate(BaseModel):
    scenario_id: int
    speed: float = Field(default=1.0, ge=0.25, le=16.0)


class SimulationOut(ORMModel):
    id: int
    scenario_id: int
    scenario_name: str = ""
    analyst_id: int
    status: str
    speed: float
    started_at: datetime | None
    sim_elapsed_sec: float = 0.0
    events_emitted: int = 0
    alerts_raised: int = 0
    completed_at: datetime | None = None
    score: dict | None = None
    created_at: datetime


class EventOut(ORMModel):
    id: int
    simulation_id: int
    timestamp: datetime
    offset_sec: float = 0.0
    event_type: str
    severity: str
    source: str | None
    destination: str | None
    username: str | None
    device: str | None
    message: str
    meta: dict


class AlertOut(ORMModel):
    id: int
    simulation_id: int
    event_id: int | None
    rule_id: str | None
    severity: str
    category: str
    title: str
    description: str
    status: str
    created_at: datetime


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(NEW|ACKNOWLEDGED|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")


class AlertDetailOut(BaseModel):
    alert: AlertOut
    event: EventOut | None
    related_alerts: list[AlertOut] = []
    related_events: list[EventOut] = []
    mitre_techniques: list[dict] = []


class FeedOut(BaseModel):
    status: str
    sim_elapsed_sec: float
    events: list[EventOut]
    new_alerts: list[AlertOut]


class IncidentCreate(BaseModel):
    simulation_id: int
    title: str = Field(min_length=3, max_length=255)
    description: str = ""
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    alert_ids: list[int] = Field(default_factory=list)


class IncidentOut(ORMModel):
    id: int
    simulation_id: int
    analyst_id: int
    title: str
    description: str
    severity: str
    status: str
    alert_ids: list[int] = []
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(DETECTED|INVESTIGATING|CONFIRMED|CONTAINED|RESOLVED)$")


class IncidentAlertsIn(BaseModel):
    alert_ids: list[int] = Field(min_length=1)


class ResponseActionIn(BaseModel):
    action_type: str = Field(pattern="^(DISABLE_USER|BLOCK_IP|ISOLATE_ENDPOINT|REVOKE_SESSION|RESET_CREDENTIAL|ESCALATE_INCIDENT|MARK_FALSE_POSITIVE|RESOLVE_INCIDENT)$")
    target: str = Field(min_length=1, max_length=255)


class ActionOut(ORMModel):
    id: int
    incident_id: int | None
    simulation_id: int
    analyst_id: int
    action_type: str
    target: str
    result: str
    timestamp: datetime


class SimAssetOut(ORMModel):
    id: int
    simulation_id: int
    asset_type: str
    identifier: str
    status: str
    meta: dict


class TimelineItem(BaseModel):
    timestamp: datetime
    kind: str  # event|alert|action|transition
    title: str
    detail: str = ""
    severity: str | None = None


class IncidentDetailOut(BaseModel):
    incident: IncidentOut
    alerts: list[AlertOut] = []
    actions: list[ActionOut] = []
    events: list[EventOut] = []
    timeline: list[TimelineItem] = []
    mitre_techniques: list[dict] = []
    assets: list[SimAssetOut] = []
