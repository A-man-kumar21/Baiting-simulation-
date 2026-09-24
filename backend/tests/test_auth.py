"""Auth: register, login, me, token handling."""
from .conftest import ADMIN, ANALYST, auth_headers, login


def test_register_creates_analyst(client):
    r = client.post("/api/auth/register",
                    json={"name": "New Analyst", "email": "new@cybersoc.sim", "password": "Password123"})
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "SOC_ANALYST"


def test_register_duplicate_email_conflict(client):
    body = {"name": "Dup", "email": "dup@cybersoc.sim", "password": "Password123"}
    assert client.post("/api/auth/register", json=body).status_code == 201
    assert client.post("/api/auth/register", json=body).status_code == 409


def test_register_short_password_rejected(client):
    r = client.post("/api/auth/register",
                    json={"name": "X", "email": "x@cybersoc.sim", "password": "short"})
    assert r.status_code == 422


def test_login_ok_and_me(client):
    token = login(client, ANALYST)
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == ANALYST["email"]


def test_login_wrong_password_401(client):
    r = client.post("/api/auth/login", json={"email": ANALYST["email"], "password": "nope"})
    assert r.status_code == 401


def test_me_no_token_401(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_bad_token_401(client):
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer bogus"}).status_code == 401


def test_passwords_are_hashed(client):
    from app.db.session import SessionLocal
    from app.models.user import User
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == ANALYST["email"]).first()
        assert u.password_hash != ANALYST["password"]
        assert u.password_hash.startswith("$2b$")
    finally:
        db.close()
