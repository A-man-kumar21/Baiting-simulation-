"""Scenario endpoints. Analysts never see solution fields."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.scenario import MitreTechnique, Scenario, ScenarioTechnique
from app.models.user import User
from app.schemas.common import Paginated
from app.schemas.scenario import (
    MitreTechniqueOut, ScenarioCreate, ScenarioDetailOut, ScenarioListOut, ScenarioUpdate,
    SOLUTION_FIELDS,
)
from app.services.audit import audit

router = APIRouter(prefix="/scenarios", tags=["Scenarios"])


def _strip_solutions(definition: dict, is_admin: bool) -> dict:
    if is_admin:
        return definition
    return {k: v for k, v in (definition or {}).items() if k not in SOLUTION_FIELDS}


def _to_list_out(sc: Scenario) -> ScenarioListOut:
    return ScenarioListOut(
        id=sc.id, name=sc.name, description=sc.description, attack_type=sc.attack_type,
        difficulty=sc.difficulty, is_active=sc.is_active,
        event_count=len((sc.definition or {}).get("event_sequence", [])),
        technique_ids=[t.technique_id for t in sc.techniques],
        created_at=sc.created_at,
    )


@router.get("", response_model=Paginated[ScenarioListOut])
def list_scenarios(active_only: bool = Query(True), skip: int = 0, limit: int = 50,
                   db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q = db.query(Scenario).order_by(Scenario.id)
    if active_only or user.role != "ADMIN":
        q = q.filter(Scenario.is_active.is_(True))
    items = [_to_list_out(s) for s in q.offset(skip).limit(limit).all()]
    return {"items": items, "total": q.count()}


@router.get("/{scenario_id}", response_model=ScenarioDetailOut)
def get_scenario(scenario_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    sc = db.get(Scenario, scenario_id)
    if not sc or (not sc.is_active and user.role != "ADMIN"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found")
    is_admin = user.role == "ADMIN"
    base = _to_list_out(sc)
    return ScenarioDetailOut(
        **base.model_dump(),
        initial_state=sc.initial_state,
        definition=_strip_solutions(sc.definition, is_admin),
        techniques=[MitreTechniqueOut.model_validate(t) for t in sc.techniques],
    )


def _resolve_techniques(db: Session, technique_ids: list[str]) -> list[MitreTechnique]:
    out = []
    for tid in technique_ids:
        t = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
        if not t:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown MITRE technique {tid}")
        out.append(t)
    return out


@router.post("", response_model=ScenarioDetailOut, status_code=status.HTTP_201_CREATED)
def create_scenario(body: ScenarioCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = Scenario(name=body.name, description=body.description, attack_type=body.attack_type,
                  difficulty=body.difficulty, initial_state=body.initial_state,
                  definition=body.definition, is_active=body.is_active)
    db.add(sc)
    db.flush()
    for t in _resolve_techniques(db, body.technique_ids):
        db.add(ScenarioTechnique(scenario_id=sc.id, technique_id=t.id))
    audit(db, user_id=admin.id, action="scenario.create", resource="scenario", resource_id=sc.id)
    db.commit()
    db.refresh(sc)
    return get_scenario(sc.id, db, admin)


@router.put("/{scenario_id}", response_model=ScenarioDetailOut)
def update_scenario(scenario_id: int, body: ScenarioUpdate, db: Session = Depends(get_db),
                    admin: User = Depends(require_admin)):
    sc = db.get(Scenario, scenario_id)
    if not sc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found")
    for field in ("name", "description", "attack_type", "difficulty", "initial_state", "definition", "is_active"):
        val = getattr(body, field)
        if val is not None:
            setattr(sc, field, val)
    if body.technique_ids is not None:
        db.query(ScenarioTechnique).filter(ScenarioTechnique.scenario_id == sc.id).delete()
        for t in _resolve_techniques(db, body.technique_ids):
            db.add(ScenarioTechnique(scenario_id=sc.id, technique_id=t.id))
    audit(db, user_id=admin.id, action="scenario.update", resource="scenario", resource_id=sc.id)
    db.commit()
    db.refresh(sc)
    return get_scenario(sc.id, db, admin)


@router.delete("/{scenario_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scenario(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.get(Scenario, scenario_id)
    if not sc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found")
    sc.is_active = False  # soft delete keeps history intact
    audit(db, user_id=admin.id, action="scenario.delete", resource="scenario", resource_id=sc.id)
    db.commit()
