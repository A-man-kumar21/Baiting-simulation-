"""Post-simulation incident report generation."""
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Action, Incident
from app.models.scenario import Scenario
from app.models.simulation import SimulationSession
from app.models.user import User


def build_report(db: Session, sess: SimulationSession) -> dict:
    scenario = db.get(Scenario, sess.scenario_id)
    analyst = db.get(User, sess.analyst_id)
    definition = scenario.definition or {}
    events = db.query(Event).filter(Event.simulation_id == sess.id).order_by(Event.timestamp).all()
    alerts = db.query(Alert).filter(Alert.simulation_id == sess.id).order_by(Alert.created_at).all()
    incidents = db.query(Incident).filter(Incident.simulation_id == sess.id).order_by(Incident.created_at).all()
    actions = db.query(Action).filter(Action.simulation_id == sess.id).order_by(Action.timestamp).all()

    expected = {(e["action_type"], e["target"].lower()) for e in definition.get("expected_actions", [])}
    taken = {(a.action_type, a.target.lower()) for a in actions}
    containment = [a for a in actions if a.action_type in
                   {"DISABLE_USER", "BLOCK_IP", "ISOLATE_ENDPOINT", "REVOKE_SESSION", "RESET_CREDENTIAL"}]

    techniques = [{"technique_id": t.technique_id, "name": t.name, "description": t.description}
                  for t in scenario.techniques]

    recommendations = []
    for exp in (sess.score or {}).get("explanations", []):
        recommendations.append(exp)
    recommendations.append("Review the MITRE ATT&CK techniques above to understand each attack stage.")
    recommendations.append("In a real SOC, escalate to the incident response team before taking disruptive actions.")

    return {
        "simulation_id": sess.id,
        "scenario": {"id": scenario.id, "name": scenario.name, "attack_type": scenario.attack_type,
                     "difficulty": scenario.difficulty,
                     "story": definition.get("story", "")},
        "analyst": {"id": analyst.id, "name": analyst.name} if analyst else None,
        "started_at": sess.started_at.isoformat() if sess.started_at else None,
        "ended_at": sess.completed_at.isoformat() if sess.completed_at else None,
        "status": sess.status,
        "attack_timeline": [
            {"timestamp": e.timestamp.isoformat(), "event_type": e.event_type, "severity": e.severity,
             "message": e.message, "username": e.username, "source": e.source, "destination": e.destination}
            for e in events
        ],
        "detected_indicators": [
            {"alert_id": a.id, "severity": a.severity, "title": a.title, "status": a.status,
             "created_at": a.created_at.isoformat()} for a in alerts
        ],
        "incidents": [
            {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status,
             "alert_count": len(i.alerts)} for i in incidents
        ],
        "actions_taken": [
            {"action_type": a.action_type, "target": a.target, "result": a.result,
             "timestamp": a.timestamp.isoformat(),
             "expected": (a.action_type, a.target.lower()) in expected}
            for a in actions
        ],
        "containment_actions": [a.action_type for a in containment],
        "mitre_techniques": techniques,
        "attack_chain": definition.get("attack_chain", []),
        "score": sess.score,
        "recommendations": recommendations,
        "simulation_note": "All events, users, IPs, files, and actions in this report are simulated training data.",
    }
