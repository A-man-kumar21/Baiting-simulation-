"""RBAC: analysts are fenced out of admin endpoints."""
from .conftest import auth_headers


def test_analyst_cannot_list_users(client, analyst_headers):
    assert client.get("/api/users", headers=analyst_headers).status_code == 403


def test_admin_can_list_users(client, admin_headers):
    r = client.get("/api/users", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_analyst_cannot_create_scenario(client, analyst_headers):
    r = client.post("/api/scenarios", headers=analyst_headers, json={
        "name": "X", "description": "0123456789ab", "attack_type": "Test", "definition": {}})
    assert r.status_code == 403


def test_analyst_cannot_view_analytics_overview(client, analyst_headers):
    assert client.get("/api/analytics/overview", headers=analyst_headers).status_code == 403


def test_admin_can_deactivate_user(client, admin_headers, analyst_headers):
    me = client.get("/api/auth/me", headers=analyst_headers).json()
    r = client.patch(f"/api/users/{me['id']}", headers=admin_headers, json={"is_active": False})
    assert r.status_code == 200
    assert r.json()["is_active"] is False
    # deactivated user can no longer log in
    assert client.post("/api/auth/login",
                       json={"email": me["email"], "password": "Analyst123!"}).status_code == 401


def test_admin_cannot_deactivate_self(client, admin_headers):
    me = client.get("/api/auth/me", headers=admin_headers).json()
    r = client.patch(f"/api/users/{me['id']}", headers=admin_headers, json={"is_active": False})
    assert r.status_code == 400
