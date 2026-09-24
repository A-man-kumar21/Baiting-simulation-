"""Incident lifecycle, alert correlation, and SIMULATED response actions.

Every response action mutates only database rows (sim_assets / alerts /
incidents). Nothing here touches real systems — there is no subprocess,
socket, or OS-level call anywhere in this module by design.
"""
from sqlalchemy.orm import Session

from app.models.alert import ALERT_TRANSITIONS, Alert
from app.models.incident import CONTAINMENT_ACTIONS, INCIDENT_TRANSITIONS, Action, Incident, IncidentAlert
from app.models.simulation import SimAsset, SimulationSession
from app.services.audit import audit

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _get_simulation(db: Session, analyst_id: int, simulation_id: int, allow_admin: bool, user) -> SimulationSession:
    sess = db.get(SimulationSession, simulation_id)
    if not sess:
        raise LookupError("Simulation not found")
    if not allow_admin and sess.analyst_id != analyst_id:
        raise PermissionError("Not your simulation")
    return sess


def create_incident(db: Session, analyst, simulation_id: int, title: str,
                    description: str, severity: str, alert_ids: list[int]) -> Incident:
    sess = db.get(SimulationSession, simulation_id)
    if not sess:
        raise LookupError("Simulation not found")
    if analyst.role != "ADMIN" and sess.analyst_id != analyst.id:
        raise PermissionError("Not your simulation")
    inc = Incident(simulation_id=simulation_id, analyst_id=analyst.id,
                   title=title.strip(), description=description or "",
                   severity=severity, status="DETECTED")
    db.add(inc)
    db.flush()
    _attach_alerts(db, inc, alert_ids, analyst.id)
    audit(db, user_id=analyst.id, action="incident.create", resource="incident",
          resource_id=inc.id, meta={"simulation_id": simulation_id, "severity": severity})
    db.commit()
    db.refresh(inc)
    return inc


def _attach_alerts(db: Session, inc: Incident, alert_ids: list[int], user_id: int) -> int:
    added = 0
    existing = {a.id for a in inc.alerts}
    for aid in alert_ids:
        alert = db.get(Alert, aid)
        if not alert or alert.simulation_id != inc.simulation_id:
            raise LookupError(f"Alert {aid} not found in this simulation")
        if aid not in existing:
            db.add(IncidentAlert(incident_id=inc.id, alert_id=aid))
            added += 1
    if added:
        audit(db, user_id=user_id, action="incident.correlate", resource="incident",
              resource_id=inc.id, meta={"alert_ids": alert_ids})
    return added


def correlate_alerts(db: Session, inc: Incident, alert_ids: list[int], user_id: int) -> Incident:
    _attach_alerts(db, inc, alert_ids, user_id)
    db.commit()
    db.refresh(inc)
    return inc


def transition_incident(db: Session, inc: Incident, new_status: str, user_id: int) -> Incident:
    allowed = INCIDENT_TRANSITIONS.get(inc.status, set())
    if new_status not in allowed:
        raise ValueError(f"Cannot transition incident from {inc.status} to {new_status}")
    old = inc.status
    inc.status = new_status
    if new_status == "RESOLVED":
        from app.services.simulation_engine import utcnow
        inc.resolved_at = utcnow()
    audit(db, user_id=user_id, action="incident.transition", resource="incident",
          resource_id=inc.id, meta={"from": old, "to": new_status})
    db.commit()
    db.refresh(inc)
    return inc


def transition_alert(db: Session, alert: Alert, new_status: str, user_id: int) -> Alert:
    allowed = ALERT_TRANSITIONS.get(alert.status, set())
    if new_status not in allowed:
        raise ValueError(f"Cannot transition alert from {alert.status} to {new_status}")
    old = alert.status
    alert.status = new_status
    audit(db, user_id=user_id, action="alert.transition", resource="alert",
          resource_id=alert.id, meta={"from": old, "to": new_status})
    db.commit()
    db.refresh(alert)
    return alert


def _find_asset(db: Session, sim_id: int, asset_type: str, identifier: str) -> SimAsset | None:
    q = db.query(SimAsset).filter(
        SimAsset.simulation_id == sim_id,
        SimAsset.asset_type == asset_type,
    )
    ident = identifier.strip()
    asset = q.filter(SimAsset.identifier == ident).first()
    if not asset:
        asset = q.filter(SimAsset.identifier.ilike(ident)).first()
    return asset


def _set_asset(db: Session, asset: SimAsset | None, status: str | None,
               flag: str | None, result: str) -> str:
    """Mutate a simulated asset. Lifecycle actions replace status; flag actions
    (credential reset, session revoke) are recorded in meta so they compose
    with the lifecycle status instead of overwriting it."""
    if not asset:
        return result
    meta = dict(asset.meta or {})
    if status:
        meta.setdefault("status_history", []).append(asset.status)
        asset.status = status
    if flag:
        meta[flag] = True
    asset.meta = meta
    db.flush()
    return result


def perform_action(db: Session, inc: Incident | None, analyst, simulation_id: int,
                   action_type: str, target: str) -> tuple[Action, str]:
    """Execute a simulated response action. Returns (action_row, human_result)."""
    target = target.strip()
    result = ""
    new_incident_status = None

    if action_type == "DISABLE_USER":
        asset = _find_asset(db, simulation_id, "USER", target)
        result = _set_asset(db, asset, "DISABLED", None,
                            f"Simulated user '{asset.identifier}' disabled (simulation only).") \
            if asset else f"No simulated user '{target}' in this scenario — no effect."
    elif action_type == "BLOCK_IP":
        asset = _find_asset(db, simulation_id, "IP", target)
        result = _set_asset(db, asset, "BLOCKED", None,
                            f"Simulated IP '{asset.identifier}' blocked (simulation only; no firewall touched).") \
            if asset else f"No simulated IP '{target}' in this scenario — no effect."
    elif action_type == "ISOLATE_ENDPOINT":
        asset = _find_asset(db, simulation_id, "ENDPOINT", target)
        result = _set_asset(db, asset, "ISOLATED", None,
                            f"Simulated endpoint '{asset.identifier}' isolated (simulation only; no real host touched).") \
            if asset else f"No simulated endpoint '{target}' in this scenario — no effect."
    elif action_type == "REVOKE_SESSION":
        asset = _find_asset(db, simulation_id, "SESSION", target) or \
                _find_asset(db, simulation_id, "SESSION", f"sess-{target}")
        result = _set_asset(db, asset, None, "sessions_revoked",
                            f"Simulated session '{asset.identifier}' revoked (simulation only).") \
            if asset else f"No simulated session for '{target}' — no effect."
    elif action_type == "RESET_CREDENTIAL":
        asset = _find_asset(db, simulation_id, "USER", target)
        result = _set_asset(db, asset, None, "credentials_reset",
                            f"Credentials for simulated user '{asset.identifier}' rotated (simulation only).") \
            if asset else f"No simulated user '{target}' in this scenario — no effect."
    elif action_type == "ESCALATE_INCIDENT":
        if not inc:
            raise ValueError("ESCALATE_INCIDENT requires an incident")
        idx = SEVERITY_ORDER.index(inc.severity)
        if idx < len(SEVERITY_ORDER) - 1:
            inc.severity = SEVERITY_ORDER[idx + 1]
            result = f"Incident escalated to {inc.severity} (simulated)."
        else:
            result = "Incident already at CRITICAL; cannot escalate further."
    elif action_type == "MARK_FALSE_POSITIVE":
        aid = target.lower().replace("alert:", "").replace("#", "").strip()
        if not aid.isdigit():
            raise ValueError("MARK_FALSE_POSITIVE target must be an alert id, e.g. 'alert:12'")
        alert = db.get(Alert, int(aid))
        if not alert or alert.simulation_id != simulation_id:
            raise LookupError(f"Alert {aid} not found in this simulation")
        alert.status = "FALSE_POSITIVE"
        result = f"Alert #{alert.id} marked as false positive (simulated)."
        audit(db, user_id=analyst.id, action="alert.transition", resource="alert",
              resource_id=alert.id, meta={"from": "action", "to": "FALSE_POSITIVE"})
    elif action_type == "RESOLVE_INCIDENT":
        if not inc:
            raise ValueError("RESOLVE_INCIDENT requires an incident")
        if inc.status != "CONTAINED":
            raise ValueError("Incident must be CONTAINED before it can be resolved")
        new_incident_status = "RESOLVED"
        result = "Incident resolved (simulated)."
    else:
        raise ValueError(f"Unknown action type: {action_type}")

    action = Action(incident_id=inc.id if inc else None, simulation_id=simulation_id,
                    analyst_id=analyst.id, action_type=action_type, target=target, result=result)
    db.add(action)
    db.flush()

    # Containment actions on a CONFIRMED incident auto-advance it to CONTAINED.
    if inc and action_type in CONTAINMENT_ACTIONS and inc.status == "CONFIRMED":
        new_incident_status = "CONTAINED"
    if new_incident_status and inc:
        old = inc.status
        inc.status = new_incident_status
        if new_incident_status == "RESOLVED":
            from app.services.simulation_engine import utcnow
            inc.resolved_at = utcnow()
        audit(db, user_id=analyst.id, action="incident.transition", resource="incident",
              resource_id=inc.id, meta={"from": old, "to": new_incident_status, "via_action": action_type})

    audit(db, user_id=analyst.id, action="response.action", resource="action",
          resource_id=action.id, meta={"type": action_type, "target": target,
                                       "incident_id": inc.id if inc else None})
    db.commit()
    db.refresh(action)
    if inc:
        db.refresh(inc)
    return action, result
