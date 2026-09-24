"""Simulation engine: start, progressive feed, pause/resume/restart/complete."""
from .conftest import backdate_simulation, start_bruteforce


def test_start_and_feed_progressive(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    # fresh simulation: no events yet (first event at t=5s)
    r = client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers).json()
    assert r["status"] == "RUNNING" and r["events"] == []

    # jump the clock forward 30s -> first 6 failures materialize, not the rest
    backdate_simulation(sim_id, 30)
    r = client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers).json()
    assert 1 <= len(r["events"]) < 16, len(r["events"])
    assert all(e["event_type"] == "LOGIN_FAILURE" for e in r["events"])

    # since_event_id pagination returns only newer events
    last_id = r["events"][-1]["id"]
    backdate_simulation(sim_id, 250)
    r2 = client.get(f"/api/simulations/{sim_id}/feed?since_event_id={last_id}",
                    headers=analyst_headers).json()
    assert r2["events"] and all(e["id"] > last_id for e in r2["events"])
    types = {e["event_type"] for e in r2["events"]}
    assert "LOGIN_SUCCESS" in types and "DATA_TRANSFER" in types


def test_alerts_fire_from_rules(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    r = client.get(f"/api/simulations/{sim_id}/alerts", headers=analyst_headers).json()
    by_rule = {a["rule_id"]: a for a in r["items"]}
    assert by_rule["bf-fails"]["severity"] == "MEDIUM"
    assert by_rule["bf-success"]["severity"] == "HIGH"
    assert by_rule["bf-exfil"]["severity"] == "CRITICAL"
    # rules fire once: second feed adds no duplicates
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    r2 = client.get(f"/api/simulations/{sim_id}/alerts", headers=analyst_headers).json()
    assert r2["total"] == r["total"]


def test_pause_resume_freezes_clock(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    assert client.post(f"/api/simulations/{sim_id}/pause", headers=analyst_headers).status_code == 200
    r = client.get(f"/api/simulations/{sim_id}", headers=analyst_headers).json()
    assert r["status"] == "PAUSED"
    assert client.post(f"/api/simulations/{sim_id}/resume", headers=analyst_headers).status_code == 200
    assert client.get(f"/api/simulations/{sim_id}", headers=analyst_headers).json()["status"] == "RUNNING"


def test_restart_wipes_state(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    assert client.get(f"/api/simulations/{sim_id}/events", headers=analyst_headers).json()["total"] > 0
    client.post(f"/api/simulations/{sim_id}/restart", headers=analyst_headers)
    assert client.get(f"/api/simulations/{sim_id}/events", headers=analyst_headers).json()["total"] == 0
    assert client.get(f"/api/simulations/{sim_id}/alerts", headers=analyst_headers).json()["total"] == 0


def test_complete_scores_session(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    r = client.post(f"/api/simulations/{sim_id}/complete", headers=analyst_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "COMPLETED"
    assert body["score"]["total"] >= 0
    assert abs(sum(d["score"] for d in body["score"]["dimensions"].values()) - body["score"]["total"]) < 0.01


def test_analyst_cannot_touch_others_simulation(client, analyst_headers, admin_headers):
    from .conftest import auth_headers
    # second analyst
    client.post("/api/auth/register",
                json={"name": "Bee", "email": "b@cybersoc.sim", "password": "Password123"})
    b_headers = auth_headers(client, "b@cybersoc.sim", "Password123")
    sim_id = start_bruteforce(client, analyst_headers)
    assert client.get(f"/api/simulations/{sim_id}", headers=b_headers).status_code == 403
    # admin can see it
    assert client.get(f"/api/simulations/{sim_id}", headers=admin_headers).status_code == 200
