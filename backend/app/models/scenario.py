"""Scenario + MITRE technique models."""
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[int] = mapped_column(primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)  # e.g. T1110
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)


class ScenarioTechnique(Base):
    __tablename__ = "scenario_techniques"

    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id", ondelete="CASCADE"), primary_key=True)
    technique_id: Mapped[int] = mapped_column(ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True)


class Scenario(Base):
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(120), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(20), nullable=False, default="Medium")  # Easy|Medium|Hard
    initial_state: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    definition: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # definition holds: story, environment, event_sequence, alert_rules, attack_chain,
    #                   expected_actions, wrong_actions, mitre_technique_ids,
    #                   expected_severity, scoring notes
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    techniques: Mapped[list[MitreTechnique]] = relationship(
        "MitreTechnique", secondary="scenario_techniques", lazy="selectin"
    )
