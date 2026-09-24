"""Incident + correlation + response actions."""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# DETECTED -> INVESTIGATING -> CONFIRMED -> CONTAINED -> RESOLVED
INCIDENT_TRANSITIONS = {
    "DETECTED": {"INVESTIGATING", "CONFIRMED"},
    "INVESTIGATING": {"CONFIRMED", "DETECTED"},
    "CONFIRMED": {"CONTAINED"},
    "CONTAINED": {"RESOLVED"},
    "RESOLVED": set(),
}

CONTAINMENT_ACTIONS = {"DISABLE_USER", "BLOCK_IP", "ISOLATE_ENDPOINT", "REVOKE_SESSION", "RESET_CREDENTIAL"}


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    simulation_id: Mapped[int] = mapped_column(ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(20), default="DETECTED", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alerts: Mapped[list["Alert"]] = relationship("Alert", secondary="incident_alerts", lazy="selectin")


class Action(Base):
    """A simulated response action. Mutates sim_assets / alert / incident rows only."""
    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    simulation_id: Mapped[int] = mapped_column(ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
