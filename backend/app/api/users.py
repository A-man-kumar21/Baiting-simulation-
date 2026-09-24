"""User management (ADMIN only)."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import UserOut, UserUpdate
from app.schemas.common import Paginated
from app.services.audit import audit

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=Paginated[UserOut])
def list_users(skip: int = 0, limit: int = 50, db: Session = Depends(get_db),
               _admin: User = Depends(require_admin)):
    q = db.query(User).order_by(User.id)
    return {"items": q.offset(skip).limit(limit).all(), "total": q.count()}


@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id and body.is_active is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot deactivate yourself")
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    audit(db, user_id=admin.id, action="user.update", resource="user", resource_id=user.id,
          meta={"role": user.role, "is_active": user.is_active})
    db.commit()
    db.refresh(user)
    return user
