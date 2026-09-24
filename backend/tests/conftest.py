"""Test setup: file-based SQLite, seeded demo data, auth helpers."""
import os

os.environ["DATABASE_URL"] = "sqlite:////tmp/cybersoc_test.db"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-32-bytes-long!!"
os.environ["SEED_DEMO_USERS"] = "true"
# Rate limits would otherwise 429 the rapid test logins; the limiter itself
# is exercised implicitly, these values just keep the suite fast.
os.environ["RATE_LIMIT_LOGIN_PER_MIN"] = "10000"
os.environ["RATE_LIMIT_REGISTER_PER_MIN"] = "10000"

import pytest
from fastapi.testclient import TestClient

import app.models  # noqa: F401
from app.db.base import Base
from app.db.seed import seed_mitre, seed_scenarios, seed_users
from app.db.session import SessionLocal, engine, get_db
from app.main import app

ADMIN = {"email": "admin@cybersoc.sim", "password": "Admin123!"}
ANALYST = {"email": "analyst@cybersoc.sim", "password": "Analyst123!"}


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_users(db)
        techs = seed_mitre(db)
        seed_scenarios(db, techs)
    finally:
        db.close()

    def override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def login(client, creds) -> str:
    r = client.post("/api/auth/login", json=creds)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture()
def admin_headers(client):
    return {"Authorization": f"Bearer {login(client, ADMIN)}"}


@pytest.fixture()
def analyst_headers(client):
    return {"Authorization": f"Bearer {login(client, ANALYST)}"}


def auth_headers(client, email, password):
    return {"Authorization": f"Bearer {login(client, {'email': email, 'password': password})}"}


def backdate_simulation(sim_id: int, seconds_ago: float):
    """Move a simulation's start into the past so events materialize instantly."""
    from datetime import datetime, timedelta, timezone
    from app.models.simulation import SimulationSession
    db = SessionLocal()
    try:
        sess = db.get(SimulationSession, sim_id)
        sess.started_at = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
        db.commit()
    finally:
        db.close()


def start_bruteforce(client, headers, speed: float = 1.0) -> int:
    r = client.get("/api/scenarios", headers=headers)
    sc = next(s for s in r.json()["items"] if "Brute Force" in s["name"])
    r = client.post("/api/simulations", json={"scenario_id": sc["id"], "speed": speed}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]
