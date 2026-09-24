"""Simulation engine: clock-based progressive event materialization.

No background workers — the sim clock is derived from wall time minus paused
time, and due events are materialized lazily on every /feed poll. Deterministic
and trivially testable.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.scenario import Scenario
from app.models.simulation import SimAsset, SimulationSession
from app.services import alert_engine
from app.services.audit import audit

VALID_STATUSES = {"CREATED", "RUNNING", "PAUSED", "COMPLETED", "ABORTED"}


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sim_elapsed_seconds(sess: SimulationSession, now: datetime | None = None) -> float:
    now = _aware(now) or utcnow()
    started = _aware(sess.started_at)
    if not started:
        return 0.0
    if sess.status == "PAUSED" and sess.paused_at:
        end = _aware(sess.paused_at)
    else:
        end = now
    return max(0.0, (end - started).total_seconds() - sess.paused_total_sec)


def effective_offset(raw_offset: float, speed: float) -> float:
    return raw_offset / max(speed, 0.01)


def start_session(db: Session, scenario: Scenario, analyst_id: int, speed: float = 1.0) -> SimulationSession:
    sess = SimulationSession(scenario_id=scenario.id, analyst_id=analyst_id,
                             status="RUNNING", speed=speed, started_at=utcnow())
    db.add(sess)
    db.flush()
    _seed_assets(db, sess, scenario.definition)
    audit(db, user_id=analyst_id, action="simulation.start", resource="simulation",
          resource_id=sess.id, meta={"scenario_id": scenario.id, "speed": speed})
    db.commit()
    db.refresh(sess)
    return sess


def _seed_assets(db: Session, sess: SimulationSession, definition: dict) -> None:
    env = definition.get("environment", {})
    users = set(env.get("users", [])) | {env.get("victim"), env.get("insider")} - {None}
    devices = set(env.get("devices", [])) | {env.get("endpoint"), env.get("server")} - {None}
    ips = {env.get("attacker_ip")} - {None}
    for u in sorted(users):
        db.add(SimAsset(simulation_id=sess.id, asset_type="USER", identifier=u, status="ACTIVE"))
        db.add(SimAsset(simulation_id=sess.id, asset_type="SESSION", identifier=f"sess-{u}", status="ACTIVE",
                        meta={"username": u}))
    for d in sorted(devices):
        db.add(SimAsset(simulation_id=sess.id, asset_type="ENDPOINT", identifier=d, status="ACTIVE"))
    for ip in sorted(ips):
        db.add(SimAsset(simulation_id=sess.id, asset_type="IP", identifier=ip, status="ACTIVE"))


def pause_session(db: Session, sess: SimulationSession, user_id: int) -> SimulationSession:
    if sess.status != "RUNNING":
        raise ValueError("Only a running simulation can be paused")
    sess.status = "PAUSED"
    sess.paused_at = utcnow()
    audit(db, user_id=user_id, action="simulation.pause", resource="simulation", resource_id=sess.id)
    db.commit()
    db.refresh(sess)
    return sess


def resume_session(db: Session, sess: SimulationSession, user_id: int) -> SimulationSession:
    if sess.status != "PAUSED":
        raise ValueError("Only a paused simulation can be resumed")
    now = utcnow()
    paused_at = _aware(sess.paused_at) or now
    sess.paused_total_sec += (now - paused_at).total_seconds()
    sess.paused_at = None
    sess.status = "RUNNING"
    audit(db, user_id=user_id, action="simulation.resume", resource="simulation", resource_id=sess.id)
    db.commit()
    db.refresh(sess)
    return sess


def restart_session(db: Session, sess: SimulationSession, user_id: int) -> SimulationSession:
    from app.models.alert import Alert
    from app.models.event import Event
    from app.models.incident import Action, Incident, IncidentAlert
    # Wipe run state, keep the session row + audit trail.
    db.query(IncidentAlert).filter(
        IncidentAlert.incident_id.in_(db.query(Incident.id).filter(Incident.simulation_id == sess.id))).delete(synchronize_session=False)
    db.query(Action).filter(Action.simulation_id == sess.id).delete()
    db.query(Alert).filter(Alert.simulation_id == sess.id).delete()
    db.query(Event).filter(Event.simulation_id == sess.id).delete()
    db.query(Incident).filter(Incident.simulation_id == sess.id).delete()
    db.query(SimAsset).filter(SimAsset.simulation_id == sess.id).delete()
    sess.status = "RUNNING"
    sess.started_at = utcnow()
    sess.paused_at = None
    sess.paused_total_sec = 0.0
    sess.last_materialized_offset = 0.0
    sess.fired_rule_ids = []
    sess.completed_at = None
    sess.score = None
    db.flush()
    scenario = db.get(Scenario, sess.scenario_id)
    _seed_assets(db, sess, scenario.definition)
    audit(db, user_id=user_id, action="simulation.restart", resource="simulation", resource_id=sess.id)
    db.commit()
    db.refresh(sess)
    return sess


def abort_session(db: Session, sess: SimulationSession, user_id: int) -> SimulationSession:
    if sess.status in ("COMPLETED", "ABORTED"):
        raise ValueError("Simulation already finished")
    sess.status = "ABORTED"
    sess.completed_at = utcnow()
    audit(db, user_id=user_id, action="simulation.abort", resource="simulation", resource_id=sess.id)
    db.commit()
    db.refresh(sess)
    return sess


def complete_session(db: Session, sess: SimulationSession, user_id: int) -> SimulationSession:
    from app.services import scoring_engine
    if sess.status in ("COMPLETED", "ABORTED"):
        raise ValueError("Simulation already finished")
    # Flush any remaining due events before scoring.
    materialize(db, sess)
    sess.status = "COMPLETED"
    sess.completed_at = utcnow()
    sess.score = scoring_engine.score_session(db, sess)
    audit(db, user_id=user_id, action="simulation.complete", resource="simulation", resource_id=sess.id,
          meta={"score": (sess.score or {}).get("total")})
    db.commit()
    db.refresh(sess)
    return sess


def materialize(db: Session, sess: SimulationSession, now: datetime | None = None):
    """Emit due events + evaluate alert rules. Returns (new_events, new_alerts)."""
    from app.models.event import Event
    if sess.status != "RUNNING":
        return [], []
    now = _aware(now) or utcnow()
    scenario = db.get(Scenario, sess.scenario_id)
    definition = scenario.definition or {}
    seq = definition.get("event_sequence", [])
    elapsed = sim_elapsed_seconds(sess, now)

    new_events: list[Event] = []
    max_offset = sess.last_materialized_offset
    started = _aware(sess.started_at)
    for spec in sorted(seq, key=lambda e: e["offset_sec"]):
        eff = effective_offset(spec["offset_sec"], sess.speed)
        if eff <= elapsed and eff > sess.last_materialized_offset + 1e-9:
            ev = Event(
                simulation_id=sess.id,
                timestamp=started + timedelta(seconds=eff),
                event_type=spec["event_type"],
                severity=spec.get("severity", "LOW"),
                source=spec.get("source"),
                destination=spec.get("destination"),
                username=spec.get("username"),
                device=spec.get("device"),
                message=spec.get("message", ""),
                meta=spec.get("meta", {}),
                offset_sec=eff,
            )
            db.add(ev)
            new_events.append(ev)
            max_offset = max(max_offset, eff)
    if new_events:
        db.flush()
        sess.last_materialized_offset = max_offset
        new_alerts = alert_engine.evaluate(db, sess, definition.get("alert_rules", []))
        db.commit()
    else:
        new_alerts = []
        # Still evaluate rules: count/sequence rules may fire on already-emitted events
        # as the window slides (cheap; rules fire once).
        pending = [r for r in definition.get("alert_rules", []) if r.get("id") not in (sess.fired_rule_ids or [])]
        if pending:
            new_alerts = alert_engine.evaluate(db, sess, pending)
            if new_alerts:
                db.commit()
    # Auto-complete grace: all events out + 90s sim-time of quiet -> finish & score.
    if seq:
        last = max(effective_offset(e["offset_sec"], sess.speed) for e in seq)
        if elapsed > last + 90 and sess.status == "RUNNING":
            from app.services import scoring_engine
            sess.status = "COMPLETED"
            sess.completed_at = utcnow()
            sess.score = scoring_engine.score_session(db, sess)
            audit(db, user_id=sess.analyst_id, action="simulation.auto_complete",
                  resource="simulation", resource_id=sess.id, meta={"score": (sess.score or {}).get("total")})
            db.commit()
    db.refresh(sess)
    return new_events, new_alerts
