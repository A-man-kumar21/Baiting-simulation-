"""Incident endpoints: create, correlate, lifecycle, response actions, investigation."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.simulations import _get_owned
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Action, Incident
from app.models.scenario import Scenario
from app.models.simulation import SimAsset, SimulationSession
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.sim import (
    ActionOut, AlertOut, EventOut, IncidentAlertsIn, IncidentCreate, IncidentDetailOut,
    IncidentOut, IncidentStatusUpdate, ResponseActionIn, SimAssetOut, TimelineItem,
)
from app.services import incident_service
from app.services.simulation_engine import sim_elapsed_seconds

router = APIRouter(prefix="/incidents", tags=["Incidents"])


def _get_incident(db: Session, user: User, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    _get_owned(db, user, inc.simulation_id)
    return inc


def _serialize(inc: Incident) -> IncidentOut:
    return IncidentOut(
        id=inc.id, simulation_id=inc.simulation_id, analyst_id=inc.analyst_id,
        title=inc.title, description=inc.description, severity=inc.severity, status=inc.status,
        alert_ids=[a.id for a in inc.alerts], created_at=inc.created_at,
        updated_at=inc.updated_at, resolved_at=inc.resolved_at,
    )


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def create_incident(body: IncidentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        inc = incident_service.create_incident(db, user, body.simulation_id, body.title,
                                               body.description, body.severity, body.alert_ids)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    except PermissionError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))
    return _serialize(inc)


@router.get("", response_model=Paginated[IncidentOut])
def list_incidents(simulation_id: int | None = Query(None), status: str | None = Query(None),
                   skip: int = 0, limit: int = 50,
                   db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Incident).order_by(Incident.created_at.desc())
    if user.role != "ADMIN":
        q = q.join(SimulationSession, Incident.simulation_id == SimulationSession.id)\
             .filter(SimulationSession.analyst_id == user.id)
    if simulation_id:
        if user.role != "ADMIN":
            _get_owned(db, user, simulation_id)
        q = q.filter(Incident.simulation_id == simulation_id)
    if status:
        q = q.filter(Incident.status == status)
    items = q.offset(skip).limit(limit).all()
    return {"items": [_serialize(i) for i in items], "total": q.count()}


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def incident_detail(incident_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inc = _get_incident(db, user, incident_id)
    sess = db.get(SimulationSession, inc.simulation_id)
    scenario = db.get(Scenario, sess.scenario_id) if sess else None
    alerts = sorted(inc.alerts, key=lambda a: a.created_at)
    actions = db.query(Action).filter(Action.incident_id == inc.id).order_by(Action.timestamp).all()
    # also show sim-level actions not tied to this incident
    sim_actions = db.query(Action).filter(Action.simulation_id == inc.simulation_id,
                                          Action.incident_id.is_(None)).order_by(Action.timestamp).all()
    events = db.query(Event).filter(Event.simulation_id == inc.simulation_id).order_by(Event.timestamp).limit(300).all()
    assets = db.query(SimAsset).filter(SimAsset.simulation_id == inc.simulation_id).all()

    timeline: list[TimelineItem] = []
    for a in alerts:
        timeline.append(TimelineItem(timestamp=a.created_at, kind="alert",
                                     title=f"ALERT: {a.title}", detail=a.description, severity=a.severity))
    for act in actions + sim_actions:
        timeline.append(TimelineItem(timestamp=act.timestamp, kind="action",
                                     title=f"{act.action_type} -> {act.target}", detail=act.result))
    timeline.append(TimelineItem(timestamp=inc.created_at, kind="transition",
                                 title=f"Incident created (status {inc.status})", detail=inc.title))
    if inc.resolved_at:
        timeline.append(TimelineItem(timestamp=inc.resolved_at, kind="transition",
                                     title="Incident resolved", detail=""))
    timeline.sort(key=lambda i: i.timestamp)

    techniques = [{"technique_id": t.technique_id, "name": t.name, "description": t.description}
                  for t in (scenario.techniques if scenario else [])]
    return IncidentDetailOut(
        incident=_serialize(inc),
        alerts=[AlertOut.model_validate(a) for a in alerts],
        actions=[ActionOut.model_validate(a) for a in actions + sim_actions],
        events=[EventOut.model_validate(e) for e in events],
        timeline=timeline,
        mitre_techniques=techniques,
        assets=[SimAssetOut.model_validate(a) for a in assets],
    )


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, body: IncidentStatusUpdate,
                    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inc = _get_incident(db, user, incident_id)
    try:
        incident_service.transition_incident(db, inc, body.status, user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return _serialize(inc)


@router.post("/{incident_id}/alerts", response_model=IncidentOut)
def correlate(incident_id: int, body: IncidentAlertsIn,
              db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inc = _get_incident(db, user, incident_id)
    try:
        incident_service.correlate_alerts(db, inc, body.alert_ids, user.id)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return _serialize(inc)


@router.post("/{incident_id}/actions", response_model=dict)
def response_action(incident_id: int, body: ResponseActionIn,
                    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    inc = _get_incident(db, user, incident_id)
    try:
        action, result = incident_service.perform_action(db, inc, user, inc.simulation_id,
                                                         body.action_type, body.target)
    except (ValueError, LookupError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return {"action": ActionOut.model_validate(action), "result": result,
            "incident_status": inc.status}
