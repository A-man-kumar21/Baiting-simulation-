"""Scenarios: seed data, solution-field redaction, admin CRUD."""
import pytest


def test_six_scenarios_seeded(client, analyst_headers):
    r = client.get("/api/scenarios", headers=analyst_headers)
    assert r.status_code == 200
    names = {s["name"] for s in r.json()["items"]}
    assert len(names) >= 6
    for needle in ("Brute Force", "Phishing", "Privilege Escalation", "Ransomware", "Insider", "Web Application"):
        assert any(needle in n for n in names), needle


def test_analyst_detail_hides_solutions(client, analyst_headers):
    sid = client.get("/api/scenarios", headers=analyst_headers).json()["items"][0]["id"]
    r = client.get(f"/api/scenarios/{sid}", headers=analyst_headers)
    assert r.status_code == 200
    definition = r.json()["definition"]
    for field in ("expected_actions", "wrong_actions", "scoring", "expected_severity"):
        assert field not in definition, field
    # but story + attack chain are visible
    assert "story" in definition and "attack_chain" in definition


def test_admin_detail_shows_solutions(client, admin_headers):
    sid = client.get("/api/scenarios", headers=admin_headers).json()["items"][0]["id"]
    r = client.get(f"/api/scenarios/{sid}", headers=admin_headers)
    assert "expected_actions" in r.json()["definition"]


def test_admin_crud_scenario(client, admin_headers):
    body = {"name": "Custom Test Scenario", "description": "A custom scenario for testing purposes.",
            "attack_type": "Test", "difficulty": "Easy",
            "definition": {"story": "x", "event_sequence": [], "alert_rules": []},
            "technique_ids": ["T1110"]}
    r = client.post("/api/scenarios", headers=admin_headers, json=body)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert any(t["technique_id"] == "T1110" for t in r.json()["techniques"])

    r = client.put(f"/api/scenarios/{sid}", headers=admin_headers, json={"difficulty": "Hard"})
    assert r.status_code == 200 and r.json()["difficulty"] == "Hard"

    assert client.delete(f"/api/scenarios/{sid}", headers=admin_headers).status_code == 204
    # soft delete: gone from analyst listing
    ids = {s["id"] for s in client.get("/api/scenarios", headers=admin_headers).json()["items"]}
    assert sid not in ids


def test_create_scenario_unknown_technique_rejected(client, admin_headers):
    body = {"name": "Bad", "description": "0123456789abcdef", "attack_type": "Test",
            "definition": {}, "technique_ids": ["T9999"]}
    assert client.post("/api/scenarios", headers=admin_headers, json=body).status_code == 422


def test_mitre_techniques_listed(client, analyst_headers):
    r = client.get("/api/mitre/techniques", headers=analyst_headers)
    ids = {t["technique_id"] for t in r.json()}
    assert {"T1110", "T1078", "T1041", "T1068", "T1486", "T1190"} <= ids
