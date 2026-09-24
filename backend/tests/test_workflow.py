"""Alerts lifecycle + incidents + simulated response actions + scoring + analytics."""
from .conftest import backdate_simulation, start_bruteforce


def _alerts(client, headers, sim_id):
    return client.get(f"/api/simulations/{sim_id}/alerts", headers=headers).json()["items"]


def test_alert_lifecycle(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    alert = _alerts(client, analyst_headers, sim_id)[0]
    assert alert["status"] == "NEW"
    for nxt in ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"):
        r = client.patch(f"/api/alerts/{alert['id']}", headers=analyst_headers, json={"status": nxt})
        assert r.status_code == 200, r.text
        alert = r.json()
    assert alert["status"] == "RESOLVED"
    # terminal: cannot reopen
    assert client.patch(f"/api/alerts/{alert['id']}", headers=analyst_headers,
                        json={"status": "NEW"}).status_code == 400


def test_alert_detail_shows_context(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    alert = next(a for a in _alerts(client, analyst_headers, sim_id) if a["rule_id"] == "bf-success")
    r = client.get(f"/api/alerts/{alert['id']}", headers=analyst_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["event"]["event_type"] == "LOGIN_SUCCESS"
    assert body["related_alerts"] and body["related_events"]
    assert any(t["technique_id"] == "T1110" for t in body["mitre_techniques"])


def _full_response_run(client, headers, do_expected=True):
    """Drive a brute-force sim: triage alerts, create incident, act, resolve."""
    sim_id = start_bruteforce(client, headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=headers)
    alerts = _alerts(client, headers, sim_id)
    for a in alerts:
        client.patch(f"/api/alerts/{a['id']}", headers=headers, json={"status": "ACKNOWLEDGED"})
    r = client.post("/api/incidents", headers=headers, json={
        "simulation_id": sim_id, "title": "Brute force on employee_42",
        "description": "Correlated brute-force chain", "severity": "HIGH",
        "alert_ids": [a["id"] for a in alerts]})
    assert r.status_code == 201, r.text
    inc = r.json()
    assert client.patch(f"/api/incidents/{inc['id']}", headers=headers,
                        json={"status": "INVESTIGATING"}).status_code == 200
    assert client.patch(f"/api/incidents/{inc['id']}", headers=headers,
                        json={"status": "CONFIRMED"}).status_code == 200
    # invalid jump is rejected
    bad = client.post("/api/incidents", headers=headers, json={
        "simulation_id": sim_id, "title": "x22", "description": "", "severity": "LOW", "alert_ids": []})
    inc2 = bad.json()
    assert client.patch(f"/api/incidents/{inc2['id']}", headers=headers,
                        json={"status": "RESOLVED"}).status_code == 400

    actions = [("DISABLE_USER", "employee_42"), ("BLOCK_IP", "198.51.100.23"),
               ("RESET_CREDENTIAL", "employee_42"), ("REVOKE_SESSION", "employee_42")]
    if do_expected:
        for atype, target in actions:
            r = client.post(f"/api/incidents/{inc['id']}/actions", headers=headers,
                            json={"action_type": atype, "target": target})
            assert r.status_code == 200, r.text
        # containment action auto-advanced CONFIRMED -> CONTAINED
        assert r.json()["incident_status"] == "CONTAINED"
        # simulated asset actually changed
        detail = client.get(f"/api/incidents/{inc['id']}", headers=headers).json()
        user_asset = next(a for a in detail["assets"]
                          if a["asset_type"] == "USER" and a["identifier"] == "employee_42")
        assert user_asset["status"] == "DISABLED"
        r = client.post(f"/api/incidents/{inc['id']}/actions", headers=headers,
                        json={"action_type": "RESOLVE_INCIDENT", "target": "incident"})
        assert r.json()["incident_status"] == "RESOLVED"
    return sim_id


def test_incident_lifecycle_and_containment(client, analyst_headers):
    sim_id = _full_response_run(client, analyst_headers)
    incs = client.get(f"/api/incidents?simulation_id={sim_id}", headers=analyst_headers).json()["items"]
    assert any(i["status"] == "RESOLVED" for i in incs)


def test_wrong_action_penalized_in_score(client, analyst_headers):
    sim_id = _full_response_run(client, analyst_headers, do_expected=False)
    alerts = _alerts(client, analyst_headers, sim_id)
    inc = client.post("/api/incidents", headers=analyst_headers, json={
        "simulation_id": sim_id, "title": "ttt", "description": "", "severity": "HIGH",
        "alert_ids": [alerts[0]["id"]]}).json()
    client.patch(f"/api/incidents/{inc['id']}", headers=analyst_headers, json={"status": "CONFIRMED"})
    # mark the genuine alert as false positive -> wrong action
    r = client.post(f"/api/incidents/{inc['id']}/actions", headers=analyst_headers,
                    json={"action_type": "MARK_FALSE_POSITIVE", "target": f"alert:{alerts[0]['id']}"})
    assert r.status_code == 200
    client.post(f"/api/simulations/{sim_id}/complete", headers=analyst_headers)
    score = client.get(f"/api/simulations/{sim_id}", headers=analyst_headers).json()["score"]
    assert score["dimensions"]["containment"]["score"] < 25
    assert any("false positive" in e.lower() for e in score["explanations"])


def test_good_run_scores_high_with_report(client, analyst_headers):
    sim_id = _full_response_run(client, analyst_headers, do_expected=True)
    r = client.post(f"/api/simulations/{sim_id}/complete", headers=analyst_headers)
    score = r.json()["score"]
    assert score["total"] >= 80, score
    assert score["grade"] in ("A", "B")
    rep = client.get(f"/api/simulations/{sim_id}/report", headers=analyst_headers).json()
    assert rep["scenario"]["name"].startswith("Brute Force")
    assert rep["attack_timeline"] and rep["mitre_techniques"]
    assert rep["score"]["total"] == score["total"]
    assert "simulated" in rep["simulation_note"].lower()


def test_analytics(client, analyst_headers, admin_headers):
    sim_id = _full_response_run(client, analyst_headers, do_expected=True)
    client.post(f"/api/simulations/{sim_id}/complete", headers=analyst_headers)
    r = client.get("/api/analytics/overview", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["totals"]["completed"] >= 1
    assert body["totals"]["avg_score"] >= 80
    r = client.get("/api/analytics/me", headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["totals"]["completed"] >= 1
    assert r.json()["history"][0]["scenario_name"].startswith("Brute Force")


def test_ai_assist_rule_based(client, analyst_headers):
    sim_id = start_bruteforce(client, analyst_headers)
    backdate_simulation(sim_id, 250)
    client.get(f"/api/simulations/{sim_id}/feed", headers=analyst_headers)
    r = client.post("/api/ai/assist", headers=analyst_headers,
                    json={"simulation_id": sim_id, "question": "What happened?"})
    assert r.status_code == 200
    body = r.json()
    assert "simulated" in body["answer"].lower()
    assert body["suggested_actions"]  # nothing done yet -> suggestions exist
    assert "disclaimer" in body
