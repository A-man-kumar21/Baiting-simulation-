"""Analytics, MITRE, reports, AI assistant, audit log endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.simulations import _get_owned
from app.core.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.scenario import MitreTechnique, Scenario, ScenarioTechnique
from app.models.simulation import SimulationSession
from app.models.user import User
from app.schemas.auth import UserOut
from app.schemas.common import Paginated
from app.services import ai_assistant, analytics_engine, report_service
from pydantic import BaseModel, Field

# ---------- Analytics ----------
analytics_router = APIRouter(prefix="/analytics", tags=["Analytics"])


@analytics_router.get("/overview")
def overview(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    return analytics_engine.admin_overview(db)


@analytics_router.get("/me")
def me(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return analytics_engine.analyst_stats(db, user.id)


# ---------- MITRE ----------
mitre_router = APIRouter(prefix="/mitre", tags=["MITRE"])


@mitre_router.get("/techniques")
def list_techniques(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return [{"technique_id": t.technique_id, "name": t.name, "description": t.description}
            for t in db.query(MitreTechnique).order_by(MitreTechnique.technique_id).all()]


@mitre_router.get("/techniques/{technique_id}")
def get_technique(technique_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    t = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id.upper()).first()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Technique not found")
    scenarios = db.query(Scenario).join(
        ScenarioTechnique, Scenario.id == ScenarioTechnique.scenario_id,
    ).filter(ScenarioTechnique.technique_id == t.id).all()
    return {"technique_id": t.technique_id, "name": t.name, "description": t.description,
            "scenarios": [{"id": s.id, "name": s.name} for s in scenarios]}


# ---------- Reports ----------
reports_router = APIRouter(tags=["Reports"])


@reports_router.get("/simulations/{sim_id}/report")
def simulation_report(sim_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sess = _get_owned(db, user, sim_id)
    return report_service.build_report(db, sess)


@reports_router.get("/reports")
def list_reports(skip: int = Query(0), limit: int = Query(50),
                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(SimulationSession).filter(SimulationSession.status == "COMPLETED")
    if user.role != "ADMIN":
        q = q.filter(SimulationSession.analyst_id == user.id)
    q = q.order_by(SimulationSession.completed_at.desc())
    items = []
    for s in q.offset(skip).limit(limit).all():
        sc = db.get(Scenario, s.scenario_id)
        items.append({"simulation_id": s.id, "scenario_name": sc.name if sc else "?",
                      "score": (s.score or {}).get("total"), "grade": (s.score or {}).get("grade"),
                      "completed_at": s.completed_at.isoformat() if s.completed_at else None})
    return {"items": items, "total": q.count()}


# ---------- AI assistant ----------
class AssistIn(BaseModel):
    simulation_id: int | None = None
    incident_id: int | None = None
    question: str = Field(min_length=1, max_length=2000)


ai_router = APIRouter(prefix="/ai", tags=["AI"])


@ai_router.post("/assist")
def assist(body: AssistIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if body.simulation_id:
        _get_owned(db, user, body.simulation_id)
    if body.incident_id:
        from app.models.incident import Incident
        inc = db.get(Incident, body.incident_id)
        if not inc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
        _get_owned(db, user, inc.simulation_id)
    return ai_assistant.assist(db, body.simulation_id, body.incident_id, body.question)


# ---------- Audit ----------
audit_router = APIRouter(prefix="/audit", tags=["Users"])


class AuditOut(BaseModel):
    id: int
    user_id: int | None
    action: str
    resource: str
    resource_id: int | None
    timestamp: str
    meta: dict


@audit_router.get("", response_model=Paginated[AuditOut])
def list_audit(skip: int = 0, limit: int = 100,
               db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    items = [AuditOut(id=a.id, user_id=a.user_id, action=a.action, resource=a.resource,
                      resource_id=a.resource_id,
                      timestamp=a.timestamp.isoformat() if a.timestamp else "",
                      meta=a.meta or {})
             for a in q.offset(skip).limit(limit).all()]
    return {"items": items, "total": q.count()}
