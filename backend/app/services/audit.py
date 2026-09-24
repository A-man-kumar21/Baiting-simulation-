"""Audit logging helper — call on every meaningful state change."""
from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def audit(db: Session, *, user_id: int | None, action: str, resource: str,
          resource_id: int | None = None, meta: dict | None = None) -> None:
    db.add(AuditLog(user_id=user_id, action=action, resource=resource,
                    resource_id=resource_id, meta=meta or {}))
