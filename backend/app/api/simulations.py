"""Simulation session endpoints + live feed (polling)."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Action
from app.models.scenario import Scenario
from app.models.simulation import SimulationSession
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.sim import AlertOut, EventOut, FeedOut, SimulationCreate, SimulationOut, TimelineItem
from app.services import simulation_engine
from app.services.simulation_engine import sim_elapsed_seconds

router = APIRouter(prefix="/simulations", tags=["Simulations"])


def _serialize(sess: SimulationSession, db: Session) -> SimulationOut:
    scenario = db.get(Scenario, sess.scenario_id)
    return SimulationOut(
        id=sess.id, scenario_id=sess.scenario_id,
        scenario_name=scenario.name if scenario else "",
        analyst_id=sess.analyst_id, status=sess.status, speed=sess.speed,
        started_at=sess.started_at,
        sim_elapsed_sec=round(sim_elapsed_seconds(sess), 1),
        events_emitted=db.query(func.count(Event.id)).filter(Event.simulation_id == sess.id).scalar() or 0,
        alerts_raised=db.query(func.count(Alert.id)).filter(Alert.simulation_id == sess.id).scalar() or 0,
        completed_at=sess.completed_at, score=sess.score, created_at=sess.created_at,
    )


def _get_owned(db: Session, user: User, sim_id: int) -> SimulationSession:
    sess = db.get(SimulationSession, sim_id)
    if not sess:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Simulation not found")
    if user.role != "ADMIN" and sess.analyst_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your simulation")
    return sess


@router.post("", response_model=SimulationOut, status_code=status.HTTP_201_CREATED)
def start_simulation(body: SimulationCreate, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    scenario = db.get(Scenario, body.scenario_id)
    if not scenario or not scenario.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found or inactive")
    sess = simulation_engine.start_session(db, scenario, user.id, speed=body.speed)
    return _serialize(sess, db)


@router.get("", response_model=Paginated[SimulationOut])
def list_simulations(status: str | None = Query(None), analyst_id: int | None = Query(None),
                     skip: int = 0, limit: int = 50,
                     db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(SimulationSession).order_by(SimulationSession.id.desc())
    if user.role != "ADMIN":
        q = q.filter(SimulationSession.analyst_id == user.id)
    elif analyst_id:
        q = q.filter(SimulationSession.analyst_id == analyst_id)
    if status:
        q = q.filter(SimulationSession.status == status)
    return {"items": [_serialize(s, db) for s in q.offset(skip).limit(limit).all()], "total": q.count()}


@router.get("/{sim_id}", response_model=SimulationOut)
def get_simulation(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _serialize(_get_owned(db, user, sim_id), db)


@router.get("/{sim_id}/story")
def get_story(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Scenario story + attack chain for the simulation briefing (no solutions)."""
    sess = _get_owned(db, user, sim_id)
    scenario = db.get(Scenario, sess.scenario_id)
    definition = scenario.definition or {}
    return {
        "scenario_name": scenario.name,
        "story": definition.get("story", ""),
        "attack_chain": definition.get("attack_chain", []),
        "estimated_duration_sec": definition.get("estimated_duration_sec"),
        "difficulty": scenario.difficulty,
    }


@router.post("/{sim_id}/pause", response_model=SimulationOut)
def pause(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    try:
        simulation_engine.pause_session(db, sess, user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return _serialize(sess, db)


@router.post("/{sim_id}/resume", response_model=SimulationOut)
def resume(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    try:
        simulation_engine.resume_session(db, sess, user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return _serialize(sess, db)


@router.post("/{sim_id}/restart", response_model=SimulationOut)
def restart(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    simulation_engine.restart_session(db, sess, user.id)
    return _serialize(sess, db)


@router.post("/{sim_id}/complete", response_model=SimulationOut)
def complete(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    try:
        simulation_engine.complete_session(db, sess, user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return _serialize(sess, db)


@router.post("/{sim_id}/abort", response_model=SimulationOut)
def abort(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    try:
        simulation_engine.abort_session(db, sess, user.id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    return _serialize(sess, db)


@router.get("/{sim_id}/feed", response_model=FeedOut)
def feed(sim_id: int, since_event_id: int = Query(0, ge=0),
         db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Poll endpoint: materializes due events, returns new events + alerts."""
    sess = _get_owned(db, user, sim_id)
    new_events, new_alerts = simulation_engine.materialize(db, sess)
    events = db.query(Event).filter(Event.simulation_id == sim_id, Event.id > since_event_id)\
        .order_by(Event.id).limit(500).all()
    return FeedOut(
        status=sess.status,
        sim_elapsed_sec=round(sim_elapsed_seconds(sess), 1),
        events=[EventOut.model_validate(e) for e in events],
        new_alerts=[AlertOut.model_validate(a) for a in new_alerts],
    )


@router.get("/{sim_id}/timeline", response_model=list[TimelineItem])
def timeline(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    items: list[TimelineItem] = []
    for e in db.query(Event).filter(Event.simulation_id == sim_id).order_by(Event.timestamp).all():
        items.append(TimelineItem(timestamp=e.timestamp, kind="event",
                                  title=f"{e.event_type}", detail=e.message, severity=e.severity))
    for a in db.query(Alert).filter(Alert.simulation_id == sim_id).order_by(Alert.created_at).all():
        items.append(TimelineItem(timestamp=a.created_at, kind="alert",
                                  title=f"ALERT: {a.title}", detail=a.description, severity=a.severity))
    for act in db.query(Action).filter(Action.simulation_id == sim_id).order_by(Action.timestamp).all():
        items.append(TimelineItem(timestamp=act.timestamp, kind="action",
                                  title=f"{act.action_type} -> {act.target}", detail=act.result))
    items.sort(key=lambda i: i.timestamp)
    return items
