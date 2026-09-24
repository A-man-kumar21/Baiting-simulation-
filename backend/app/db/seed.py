"""Seed the database: tables, demo users, MITRE techniques, scenarios.

DEV-ONLY CREDENTIALS below — change before any production use.
Run:  python -m app.db.seed   (from backend/)
"""
import sys

from sqlalchemy.orm import Session

import app.models  # noqa: F401  (register models)
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models.scenario import MitreTechnique, Scenario, ScenarioTechnique
from app.models.user import Role, User
from app.services.seed_scenarios import MITRE_TECHNIQUES, SCENARIOS

# ---- Development-only credentials. Change before production. ----
ADMIN_EMAIL = "admin@cybersoc.sim"
ADMIN_PASSWORD = "Admin123!"
ADMIN_NAME = "SOC Admin"
ANALYST_EMAIL = "analyst@cybersoc.sim"
ANALYST_PASSWORD = "Analyst123!"
ANALYST_NAME = "Alex Analyst"


def seed_users(db: Session) -> None:
    for email, password, name, role in [
        (ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_NAME, Role.ADMIN.value),
        (ANALYST_EMAIL, ANALYST_PASSWORD, ANALYST_NAME, Role.SOC_ANALYST.value),
    ]:
        if not db.query(User).filter(User.email == email).first():
            db.add(User(name=name, email=email, password_hash=hash_password(password), role=role))
    db.commit()


def seed_mitre(db: Session) -> dict[str, MitreTechnique]:
    out = {}
    for tid, name, desc in MITRE_TECHNIQUES:
        t = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
        if not t:
            t = MitreTechnique(technique_id=tid, name=name, description=desc)
            db.add(t)
            db.flush()
        out[tid] = t
    db.commit()
    return out


def seed_scenarios(db: Session, techniques: dict[str, MitreTechnique]) -> None:
    for s in SCENARIOS:
        existing = db.query(Scenario).filter(Scenario.name == s["name"]).first()
        if existing:
            continue
        sc = Scenario(
            name=s["name"],
            description=s["description"],
            attack_type=s["attack_type"],
            difficulty=s["difficulty"],
            initial_state=s["initial_state"],
            definition=s["definition"],
            is_active=True,
        )
        db.add(sc)
        db.flush()
        for tid in s["definition"].get("mitre_technique_ids", []):
            if tid in techniques:
                db.add(ScenarioTechnique(scenario_id=sc.id, technique_id=techniques[tid].id))
    db.commit()


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_users(db)
        techniques = seed_mitre(db)
        seed_scenarios(db, techniques)
    finally:
        db.close()
    print("Seed complete: demo users, MITRE techniques, scenarios.")


if __name__ == "__main__":
    sys.exit(main())
