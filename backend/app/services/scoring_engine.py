"""Scoring engine — evaluates analyst performance per completed simulation.

Dimensions (total 100):
  detection      25  — key (HIGH/CRITICAL) alerts acknowledged/investigated
  investigation  20  — incident created + breadth of alert triage
  severity       15  — incident severity vs scenario's expected severity
  containment    25  — expected containment actions taken, wrong actions penalized
  resolution     15  — incident lifecycle progress
Plus time-to-detect / contain / resolve and human-readable explanations.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Action, Incident
from app.models.scenario import Scenario
from app.models.simulation import SimulationSession

SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
KEY_SEV = {"HIGH", "CRITICAL"}


def _aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _fmt_secs(sec: float | None) -> str:
    if sec is None:
        return "n/a"
    sec = int(sec)
    m, s = divmod(sec, 60)
    return f"{m}m {s}s" if m else f"{s}s"


def score_session(db: Session, sess: SimulationSession) -> dict:
    scenario = db.get(Scenario, sess.scenario_id)
    definition = scenario.definition or {}
    alerts = db.query(Alert).filter(Alert.simulation_id == sess.id).order_by(Alert.created_at).all()
    incidents = db.query(Incident).filter(Incident.simulation_id == sess.id).order_by(Incident.created_at).all()
    actions = db.query(Action).filter(Action.simulation_id == sess.id).order_by(Action.timestamp).all()

    explanations: list[str] = []
    dims: dict[str, float] = {}

    # ---------- Detection (25) ----------
    key_alerts = [a for a in alerts if a.severity in KEY_SEV]
    triaged = [a for a in key_alerts if a.status in ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED")]
    fp_on_key = [a for a in key_alerts if a.status == "FALSE_POSITIVE"]
    if key_alerts:
        det = 25.0 * len(triaged) / len(key_alerts)
    else:
        det = 25.0
    det -= 5 * len(fp_on_key)
    det = max(0.0, round(det, 1))
    dims["detection"] = det
    if key_alerts and len(triaged) < len(key_alerts):
        explanations.append(
            f"Detection: you triaged {len(triaged)}/{len(key_alerts)} HIGH/CRITICAL alerts "
            f"(-{round(25 - 25 * len(triaged) / len(key_alerts), 1)} pts). Acknowledge every critical alert.")
    for a in fp_on_key:
        explanations.append(f"Detection: alert #{a.id} ('{a.title}') was genuine but marked false positive (-5 pts).")

    # ---------- Investigation (20) ----------
    inv = 0.0
    if incidents:
        inv += 10.0
    else:
        explanations.append("Investigation: no incident was created from the alerts (-10 pts). Correlate related alerts into an incident.")
    if alerts:
        frac = sum(1 for a in alerts if a.status != "NEW") / len(alerts)
        inv += round(10.0 * frac, 1)
        if frac < 1.0:
            explanations.append(
                f"Investigation: {sum(1 for a in alerts if a.status == 'NEW')}/{len(alerts)} alerts were never triaged "
                f"(-{round(10 - 10 * frac, 1)} pts).")
    else:
        inv += 10.0
    dims["investigation"] = round(min(20.0, inv), 1)

    # ---------- Severity classification (15) ----------
    expected_sev = definition.get("expected_severity", "HIGH")
    sev_score = 0.0
    if incidents:
        main = max(incidents, key=lambda i: SEV_ORDER.index(i.severity))
        diff = abs(SEV_ORDER.index(main.severity) - SEV_ORDER.index(expected_sev))
        sev_score = 15.0 if diff == 0 else (7.0 if diff == 1 else 0.0)
        if diff:
            explanations.append(
                f"Severity: incident classified as {main.severity}, expected {expected_sev} (-{round(15 - sev_score, 1)} pts).")
    else:
        explanations.append("Severity: no incident to classify (-15 pts).")
    dims["severity"] = sev_score

    # ---------- Containment (25) ----------
    cont = 0.0
    expected = definition.get("expected_actions", [])
    wrong = definition.get("wrong_actions", [])
    matched_expected = set()
    for act in actions:
        for i, exp in enumerate(expected):
            if i in matched_expected:
                continue
            if (act.action_type == exp["action_type"]
                    and act.target.strip().lower() == exp["target"].strip().lower()):
                cont += exp.get("points", 5)
                matched_expected.add(i)
                break
        for w in wrong:
            wt = w.get("target", "*")
            if act.action_type == w["action_type"] and (wt == "*" or act.target.strip().lower() == wt.strip().lower()):
                cont -= w.get("penalty", 5)
                explanations.append(f"Containment: {w.get('reason', 'Wrong action')} (-{w.get('penalty', 5)} pts).")
                break
    cont = max(0.0, min(25.0, round(cont, 1)))
    dims["containment"] = cont
    missed = [e for i, e in enumerate(expected) if i not in matched_expected]
    if missed:
        explanations.append(
            "Containment: missed expected actions: " +
            ", ".join(f"{e['action_type']} {e['target']}" for e in missed) + ".")
    if not actions:
        explanations.append("Containment: no response actions were taken (-25 pts).")

    # ---------- Resolution (15) ----------
    statuses = {i.status for i in incidents}
    if "RESOLVED" in statuses:
        res = 15.0
    elif "CONTAINED" in statuses:
        res = 8.0
        explanations.append("Resolution: incident contained but never resolved (-7 pts).")
    elif "CONFIRMED" in statuses:
        res = 4.0
        explanations.append("Resolution: incident confirmed but never contained/resolved (-11 pts).")
    else:
        res = 0.0
        if incidents:
            explanations.append("Resolution: incident never progressed past initial triage (-15 pts).")
    dims["resolution"] = res

    total = round(sum(dims.values()), 1)

    # ---------- Times ----------
    times = _compute_times(sess, alerts, actions)
    if times["ttc_sec"] is not None and times["ttc_sec"] > 180:
        explanations.append(
            f"Response speed: containment took {_fmt_secs(times['ttc_sec'])} after the first alert — "
            "faster containment limits (simulated) damage.")

    grade = "A" if total >= 90 else "B" if total >= 80 else "C" if total >= 70 else "D" if total >= 60 else "F"
    return {
        "total": total,
        "grade": grade,
        "dimensions": {
            "detection": {"score": dims["detection"], "max": 25},
            "investigation": {"score": dims["investigation"], "max": 20},
            "severity": {"score": dims["severity"], "max": 15},
            "containment": {"score": dims["containment"], "max": 25},
            "resolution": {"score": dims["resolution"], "max": 15},
        },
        "times": times,
        "times_human": {k: _fmt_secs(v) for k, v in times.items()},
        "explanations": explanations,
    }


def _compute_times(sess, alerts, actions) -> dict:
    out = {"ttd_sec": None, "ttc_sec": None, "ttr_sec": None}
    key_alerts = [a for a in alerts if a.severity in KEY_SEV]
    first_alert = min(alerts, key=lambda a: _aware(a.created_at)) if alerts else None
    if key_alerts and first_alert:
        triaged = [a for a in key_alerts if a.status in ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED")]
        # ttd: first key alert -> first triage action (approx: first alert not NEW)
        first_key = min(key_alerts, key=lambda a: _aware(a.created_at))
        acked = [a for a in alerts if a.status != "NEW"]
        if acked:
            first_ack = min(acked, key=lambda a: _aware(a.updated_at))
            out["ttd_sec"] = round((_aware(first_ack.updated_at) - _aware(first_key.created_at)).total_seconds(), 1)
    from app.models.incident import CONTAINMENT_ACTIONS
    contained_acts = [a for a in actions if a.action_type in CONTAINMENT_ACTIONS]
    if contained_acts and first_alert:
        first_cont = min(contained_acts, key=lambda a: _aware(a.timestamp))
        out["ttc_sec"] = round((_aware(first_cont.timestamp) - _aware(first_alert.created_at)).total_seconds(), 1)
    if sess.completed_at and sess.started_at:
        out["ttr_sec"] = round((_aware(sess.completed_at) - _aware(sess.started_at)).total_seconds(), 1)
    return out
