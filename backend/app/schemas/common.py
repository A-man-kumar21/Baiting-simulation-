"""Shared Pydantic bits."""
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Paginated(BaseModel, Generic[T]):
    items: list[T]
    total: int


def utcnow() -> datetime:
    from datetime import timezone
    return datetime.now(timezone.utc)
