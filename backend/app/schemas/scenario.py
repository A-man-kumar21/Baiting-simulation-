"""Scenario schemas. Analyst views exclude solution fields."""
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel, Paginated

SOLUTION_FIELDS = {"expected_actions", "wrong_actions", "scoring", "expected_severity"}


class ScenarioCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=10)
    attack_type: str = Field(min_length=2, max_length=120)
    difficulty: str = Field(default="Medium", pattern="^(Easy|Medium|Hard)$")
    initial_state: dict = Field(default_factory=dict)
    definition: dict
    technique_ids: list[str] = Field(default_factory=list)  # MITRE IDs like ["T1110"]
    is_active: bool = True


class ScenarioUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, min_length=10)
    attack_type: str | None = None
    difficulty: str | None = Field(default=None, pattern="^(Easy|Medium|Hard)$")
    initial_state: dict | None = None
    definition: dict | None = None
    technique_ids: list[str] | None = None
    is_active: bool | None = None


class MitreTechniqueOut(ORMModel):
    technique_id: str
    name: str
    description: str


class ScenarioListOut(ORMModel):
    id: int
    name: str
    description: str
    attack_type: str
    difficulty: str
    is_active: bool
    event_count: int = 0
    technique_ids: list[str] = []
    created_at: datetime


class ScenarioDetailOut(ScenarioListOut):
    initial_state: dict
    definition: dict
    techniques: list[MitreTechniqueOut] = []


ScenarioListPage = Paginated[ScenarioListOut]
