"""Rule-based SOC assistant — template answers from simulation data.

No external API calls, no API keys, no model inference. The assistant explains
what happened using database rows only, and any suggested action must be
executed by the analyst through the normal (audited) action endpoints.
"""
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Action, Incident
from app.models.scenario import Scenario
from app.models.simulation import SimulationSession


def assist(db: Session, simulation_id: int | None, incident_id: int | None, question: str) -> dict:
    sess = db.get(SimulationSession, simulation_id) if simulation_id else None
    inc = db.get(Incident, incident_id) if incident_id else None
    if inc and not sess:
        sess = db.get(SimulationSession, inc.simulation_id)
    if not sess:
        return {"answer": "I need a simulation or incident to look at first.", "suggested_actions": [],
                "mitre_explanations": []}

    scenario = db.get(Scenario, sess.scenario_id)
    definition = scenario.definition or {}
    events = db.query(Event).filter(Event.simulation_id == sess.id).order_by(Event.timestamp).all()
    alerts = db.query(Alert).filter(Alert.simulation_id == sess.id).order_by(Alert.created_at).all()
    actions = db.query(Action).filter(Action.simulation_id == sess.id).all()
    taken = {(a.action_type, a.target.lower()) for a in actions}

    q = (question or "").lower()
    suggested = []
    for exp in definition.get("expected_actions", []):
        if (exp["action_type"], exp["target"].lower()) not in taken:
            suggested.append({"action_type": exp["action_type"], "target": exp["target"],
                              "why": exp.get("why", "")})
        if len(suggested) >= 3:
            break

    mitre_explanations = [
        {"technique_id": t.technique_id, "name": t.name,
         "explanation": f"In this scenario, {t.technique_id} ({t.name}) was simulated as: {t.description}"}
        for t in scenario.techniques
    ]

    if any(k in q for k in ("what happened", "summary", "summarize", "overview")):
        chain = " -> ".join(e.event_type for e in events[:12])
        crit = [a.title for a in alerts if a.severity in ("HIGH", "CRITICAL")]
        answer = (
            f"In scenario '{scenario.name}', {len(events)} simulated events were generated. "
            f"The attack chain observed: {chain}. "
            f"Key alerts raised: {'; '.join(crit) if crit else 'none yet'}. "
            f"You have taken {len(actions)} response action(s). "
            "All of this is simulated training data."
        )
    elif any(k in q for k in ("mitre", "technique", "att&ck", "attack")):
        parts = [f"{t.technique_id} — {t.name}: {t.description}" for t in scenario.techniques]
        answer = "MITRE ATT&CK techniques simulated in this scenario:\n" + "\n".join(parts)
    elif any(k in q for k in ("next", "suggest", "should i", "recommend", "investigat")):
        if suggested:
            s = suggested[0]
            answer = (f"Suggested next step: {s['action_type']} on '{s['target']}' — {s['why']} "
                      f"This is only a suggestion; run it yourself from the incident page so it is audited.")
        else:
            answer = "No further expected actions remain. Consider resolving the incident if containment is complete."
    elif any(k in q for k in ("report", "score")):
        sc = sess.score or {}
        answer = (f"Current score: {sc.get('total', 'not yet computed')} "
                  f"(grade {sc.get('grade', '-')}). Complete the simulation to finalize scoring.")
    else:
        open_alerts = [a for a in alerts if a.status in ("NEW", "ACKNOWLEDGED", "INVESTIGATING")]
        answer = (
            f"Simulation '{scenario.name}' is {sess.status}. {len(events)} events, {len(alerts)} alerts "
            f"({len(open_alerts)} open), {len(actions)} actions taken. "
            "Ask me for a summary, MITRE mapping, next-step suggestions, or the score."
        )
    return {"answer": answer, "suggested_actions": suggested, "mitre_explanations": mitre_explanations,
            "disclaimer": "Rule-based training assistant. Suggestions are advisory — the analyst must approve and execute every action."}
