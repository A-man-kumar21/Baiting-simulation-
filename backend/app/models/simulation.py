"""Simulation session + simulated assets (the 'fake infrastructure')."""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Session statuses: CREATED -> RUNNING <-> PAUSED -> COMPLETED | ABORTED
# Asset statuses are free-form per type, e.g. USER: ACTIVE|DISABLED|CREDENTIALS_RESET,
# IP: ACTIVE|BLOCKED, ENDPOINT: ACTIVE|ISOLATED, SESSION: ACTIVE|REVOKED


class SimulationSession(Base):
    __tablename__ = "simulation_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id", ondelete="RESTRICT"), nullable=False, index=True)
    analyst_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="CREATED", nullable=False, index=True)
    speed: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paused_total_sec: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_materialized_offset: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    fired_rule_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    score: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SimAsset(Base):
    """A simulated entity (user/IP/endpoint/session). Response actions mutate status here ONLY."""
    __tablename__ = "sim_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    simulation_id: Mapped[int] = mapped_column(ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # USER|IP|ENDPOINT|SESSION
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), default="ACTIVE", nullable=False)
    meta: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
