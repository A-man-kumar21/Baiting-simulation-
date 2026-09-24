"""Analytics: admin overview + analyst personal stats. Pure SQLAlchemy aggregates."""
from collections import Counter

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Action, Incident
from app.models.scenario import Scenario
from app.models.simulation import SimulationSession
from app.models.user import User
from app.services.scoring_engine import _compute_times


def _avg(values):
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 1) if vals else None


def admin_overview(db: Session) -> dict:
    sessions = db.query(SimulationSession).all()
    completed = [s for s in sessions if s.status == "COMPLETED"]
    scores = [(s.score or {}).get("total") for s in completed]
    scores = [s for s in scores if s is not None]

    ttd, ttc, ttr = [], [], []
    for s in completed:
        alerts = db.query(Alert).filter(Alert.simulation_id == s.id).all()
        actions = db.query(Action).filter(Action.simulation_id == s.id).all()
        t = _compute_times(s, alerts, actions)
        ttd.append(t["ttd_sec"]); ttc.append(t["ttc_sec"]); ttr.append(t["ttr_sec"])

    mistakes = Counter()
    for s in completed:
        for exp in (s.score or {}).get("explanations", []):
            # bucket by first clause
            mistakes[exp.split(".")[0][:80]] += 1

    scenario_stats = []
    for sc in db.query(Scenario).all():
        sc_sessions = [s for s in completed if s.scenario_id == sc.id]
        sc_scores = [(s.score or {}).get("total") for s in sc_sessions]
        sc_scores = [x for x in sc_scores if x is not None]
        scenario_stats.append({
            "scenario_id": sc.id, "name": sc.name, "difficulty": sc.difficulty,
            "runs": len(sc_sessions),
            "avg_score": round(sum(sc_scores) / len(sc_scores), 1) if sc_scores else None,
            "success_rate": round(sum(1 for x in sc_scores if x >= 70) / len(sc_scores), 2) if sc_scores else None,
        })

    attack_dist = Counter()
    for s in sessions:
        sc = db.get(Scenario, s.scenario_id)
        if sc:
            attack_dist[sc.attack_type] += 1

    analysts = []
    for u in db.query(User).filter(User.role == "SOC_ANALYST").all():
        us = [s for s in completed if s.analyst_id == u.id]
        usc = [(s.score or {}).get("total") for s in us]
        usc = [x for x in usc if x is not None]
        analysts.append({"analyst_id": u.id, "name": u.name,
                         "runs": len(us),
                         "avg_score": round(sum(usc) / len(usc), 1) if usc else None})

    return {
        "totals": {
            "simulations": len(sessions),
            "completed": len(completed),
            "running": sum(1 for s in sessions if s.status in ("RUNNING", "PAUSED")),
            "aborted": sum(1 for s in sessions if s.status == "ABORTED"),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
        },
        "avg_times_sec": {"ttd": _avg(ttd), "ttc": _avg(ttc), "ttr": _avg(ttr)},
        "scenario_stats": scenario_stats,
        "common_mistakes": [{"mistake": k, "count": v} for k, v in mistakes.most_common(10)],
        "attack_distribution": [{"attack_type": k, "count": v} for k, v in attack_dist.items()],
        "analysts": analysts,
    }


def analyst_stats(db: Session, analyst_id: int) -> dict:
    sessions = db.query(SimulationSession).filter(SimulationSession.analyst_id == analyst_id)\
        .order_by(SimulationSession.created_at.desc()).all()
    completed = [s for s in sessions if s.status == "COMPLETED"]
    scores = [(s.score or {}).get("total") for s in completed]
    scores = [s for s in scores if s is not None]

    ttd, ttc = [], []
    fp_count = missed = triaged = 0
    running = []
    history = []
    for s in sessions:
        sc = db.get(Scenario, s.scenario_id)
        alerts = db.query(Alert).filter(Alert.simulation_id == s.id).all()
        actions = db.query(Action).filter(Action.simulation_id == s.id).all()
        if s.status == "COMPLETED":
            t = _compute_times(s, alerts, actions)
            ttd.append(t["ttd_sec"]); ttc.append(t["ttc_sec"])
            fp_count += sum(1 for a in alerts if a.status == "FALSE_POSITIVE")
            missed += sum(1 for a in alerts if a.status == "NEW" and a.severity in ("HIGH", "CRITICAL"))
            sess_ttd, sess_ttc = t["ttd_sec"], t["ttc_sec"]
        else:
            sess_ttd = sess_ttc = None
        triaged += sum(1 for a in alerts if a.status != "NEW")
        if s.status in ("RUNNING", "PAUSED"):
            running.append({
                "id": s.id,
                "scenario_name": sc.name if sc else "?",
                "status": s.status,
                "alerts_raised": len(alerts),
            })
        history.append({
            "id": s.id,
            "simulation_id": s.id,
            "scenario_name": sc.name if sc else "?",
            "status": s.status,
            "score": s.score,
            "grade": (s.score or {}).get("grade"),
            "time_to_detect_sec": sess_ttd,
            "time_to_contain_sec": sess_ttc,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        })
    return {
        "totals": {
            "simulations": len(sessions),
            "completed": len(completed),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
            "best_score": max(scores) if scores else None,
            "alerts_acknowledged": triaged,
            "avg_time_to_detect_sec": _avg(ttd),
            "avg_time_to_contain_sec": _avg(ttc),
        },
        "avg_times_sec": {"ttd": _avg(ttd), "ttc": _avg(ttc)},
        "accuracy": {
            "false_positives": fp_count,
            "missed_critical_alerts": missed,
        },
        "running": running,
        "history": history,
    }
