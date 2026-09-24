"""Event query endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.simulations import _get_owned
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.event import Event
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.sim import EventOut

router = APIRouter(tags=["Events"])


@router.get("/simulations/{sim_id}/events", response_model=Paginated[EventOut])
def list_events(sim_id: int, event_type: str | None = Query(None), severity: str | None = Query(None),
                q: str | None = Query(None), skip: int = 0, limit: int = 100,
                db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _get_owned(db, user, sim_id)
    query = db.query(Event).filter(Event.simulation_id == sim_id)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if severity:
        query = query.filter(Event.severity == severity)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Event.message.ilike(like), Event.username.ilike(like),
                                 Event.source.ilike(like), Event.device.ilike(like)))
    query = query.order_by(Event.timestamp)
    return {"items": query.offset(skip).limit(limit).all(), "total": query.count()}


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    _get_owned(db, user, ev.simulation_id)
    return ev
