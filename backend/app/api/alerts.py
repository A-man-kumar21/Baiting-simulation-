"""Alert endpoints: triage queue, investigation detail, lifecycle."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.simulations import _get_owned
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.alert import Alert
from app.models.event import Event
from app.models.scenario import Scenario
from app.models.simulation import SimulationSession
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.sim import AlertDetailOut, AlertOut, AlertStatusUpdate, EventOut
from app.services import incident_service

router = APIRouter(tags=["Alerts"])


@router.get("/simulations/{sim_id}/alerts", response_model=Paginated[AlertOut])
def list_alerts(sim_id: int, status: str | None = Query(None), severity: str | None = Query(None),
                skip: int = 0, limit: int = 100,
                db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _get_owned(db, user, sim_id)
    query = db.query(Alert).filter(Alert.simulation_id == sim_id).order_by(Alert.created_at.desc())
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    return {"items": query.offset(skip).limit(limit).all(), "total": query.count()}


@router.get("/alerts", response_model=Paginated[AlertOut])
def list_all_alerts(status: str | None = Query(None), severity: str | None = Query(None),
                    simulation_id: int | None = Query(None),
                    skip: int = 0, limit: int = 100,
                    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Alert queue across simulations. Analysts see their own simulations' alerts; admins see all."""
    query = db.query(Alert).join(SimulationSession, Alert.simulation_id == SimulationSession.id)
    if user.role != "ADMIN":
        query = query.filter(SimulationSession.analyst_id == user.id)
    if simulation_id is not None:
        query = query.filter(Alert.simulation_id == simulation_id)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    query = query.order_by(Alert.created_at.desc())
    return {"items": query.offset(skip).limit(limit).all(), "total": query.count()}


@router.get("/alerts/{alert_id}", response_model=AlertDetailOut)
def alert_detail(alert_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    _get_owned(db, user, alert.simulation_id)
    event = db.get(Event, alert.event_id) if alert.event_id else None
    related_alerts = db.query(Alert).filter(
        Alert.simulation_id == alert.simulation_id, Alert.id != alert.id).order_by(Alert.created_at.desc()).limit(10).all()
    related_events: list[Event] = []
    if event:
        related_events = db.query(Event).filter(
            Event.simulation_id == alert.simulation_id,
            Event.username == event.username,
            Event.id != event.id).order_by(Event.timestamp.desc()).limit(20).all()
    sess = db.get(SimulationSession, alert.simulation_id)
    sess_scenario = db.get(Scenario, sess.scenario_id) if sess else None
    techniques = [{"technique_id": t.technique_id, "name": t.name, "description": t.description}
                  for t in (sess_scenario.techniques if sess_scenario else [])]
    return AlertDetailOut(
        alert=AlertOut.model_validate(alert),
        event=EventOut.model_validate(event) if event else None,
        related_alerts=[AlertOut.model_validate(a) for a in related_alerts],
        related_events=[EventOut.model_validate(e) for e in related_events],
        mitre_techniques=techniques,
    )


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, body: AlertStatusUpdate,
                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    _get_owned(db, user, alert.simulation_id)
    try:
        incident_service.transition_alert(db, alert, body.status, user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return alert
