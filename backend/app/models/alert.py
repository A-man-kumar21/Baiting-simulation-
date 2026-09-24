"""Alert model + lifecycle."""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# NEW -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED ; any -> FALSE_POSITIVE
ALERT_TRANSITIONS = {
    "NEW": {"ACKNOWLEDGED", "FALSE_POSITIVE"},
    "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"RESOLVED", "FALSE_POSITIVE", "ACKNOWLEDGED"},
    "RESOLVED": set(),
    "FALSE_POSITIVE": set(),
}


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    simulation_id: Mapped[int] = mapped_column(ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id", ondelete="SET NULL"), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), default="NEW", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
