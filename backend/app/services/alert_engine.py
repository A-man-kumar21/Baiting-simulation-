"""Rule-based alert engine. Rules come from the scenario definition and each
fires at most once per simulation (tracked in session.fired_rule_ids).

Rule types:
  count           N events of type T within W seconds            -> alert
  sequence        type A then type B within W seconds            -> alert
  single          any event of type T (optionally meta_flag set) -> alert
  field_threshold event of type T where meta[field] op value    -> alert
"""
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.simulation import SimulationSession


def _events(db: Session, sim_id: int) -> list[Event]:
    return db.query(Event).filter(Event.simulation_id == sim_id).order_by(Event.offset_sec).all()


def _fire(db: Session, sess: SimulationSession, rule: dict, trigger: Event) -> Alert:
    alert = Alert(
        simulation_id=sess.id,
        event_id=trigger.id,
        rule_id=rule.get("id"),
        severity=rule.get("severity", "MEDIUM"),
        category=rule.get("category", "General"),
        title=rule.get("title", "Suspicious activity"),
        description=rule.get("description", ""),
    )
    db.add(alert)
    db.flush()
    fired = list(sess.fired_rule_ids or [])
    if rule.get("id") and rule["id"] not in fired:
        fired.append(rule["id"])
    sess.fired_rule_ids = fired
    return alert


def _group_key(ev: Event, field: str | None):
    if not field:
        return "all"
    if field == "username":
        return ev.username or "unknown"
    return (ev.meta or {}).get(field, "unknown")


def evaluate(db: Session, sess: SimulationSession, rules: list[dict]) -> list[Alert]:
    events = _events(db, sess.id)
    if not events:
        return []
    fired_ids = set(sess.fired_rule_ids or [])
    alerts: list[Alert] = []
    for rule in rules:
        rid = rule.get("id")
        if rid and rid in fired_ids:
            continue
        rtype = rule.get("type")
        if rtype == "count":
            a = _eval_count(db, sess, rule, events)
        elif rtype == "sequence":
            a = _eval_sequence(db, sess, rule, events)
        elif rtype == "single":
            a = _eval_single(db, sess, rule, events)
        elif rtype == "field_threshold":
            a = _eval_field_threshold(db, sess, rule, events)
        else:
            continue
        if a:
            alerts.append(a)
            if rid:
                fired_ids.add(rid)
    return alerts


def _eval_count(db, sess, rule, events):
    window = rule.get("window_sec", 300)
    threshold = rule.get("threshold", 5)
    etype = rule["event_type"]
    groups: dict[str, list[Event]] = {}
    for ev in events:
        if ev.event_type == etype:
            groups.setdefault(_group_key(ev, rule.get("match_field")), []).append(ev)
    for key, evs in groups.items():
        for i, ev in enumerate(evs):
            in_window = [e for e in evs[i:] if e.offset_sec - ev.offset_sec <= window]
            if len(in_window) >= threshold:
                return _fire(db, sess, rule, in_window[-1])
    return None


def _eval_sequence(db, sess, rule, events):
    window = rule.get("window_sec", 300)
    first_t, second_t = rule["first_type"], rule["second_type"]
    match_field = rule.get("match_field")
    firsts = [e for e in events if e.event_type == first_t]
    seconds = [e for e in events if e.event_type == second_t]
    for s in seconds:
        for f in firsts:
            if 0 < s.offset_sec - f.offset_sec <= window:
                if match_field and _group_key(s, match_field) != _group_key(f, match_field):
                    continue
                return _fire(db, sess, rule, s)
    return None


def _eval_single(db, sess, rule, events):
    etype = rule["event_type"]
    flag = rule.get("meta_flag")
    for ev in events:
        if ev.event_type != etype:
            continue
        if flag and not (ev.meta or {}).get(flag):
            continue
        return _fire(db, sess, rule, ev)
    return None


def _eval_field_threshold(db, sess, rule, events):
    etype = rule["event_type"]
    field = rule["field"]
    op = rule.get("op", ">")
    value = rule["value"]
    for ev in events:
        if ev.event_type != etype:
            continue
        actual = (ev.meta or {}).get(field)
        if actual is None:
            continue
        hit = {" >": actual > value, ">": actual > value, ">=": actual >= value,
               "<": actual < value, "<=": actual <= value, "==": actual == value}.get(op, False)
        if hit:
            return _fire(db, sess, rule, ev)
    return None
