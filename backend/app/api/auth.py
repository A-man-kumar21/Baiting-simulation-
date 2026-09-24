"""Auth endpoints: register / login / me."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.auth import LoginIn, RegisterIn, TokenOut, UserOut
from app.services.audit import audit

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if db.query(User).filter(func.lower(User.email) == email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    # First-ever user becomes ADMIN (bootstrap); everyone else is an analyst.
    role = Role.ADMIN.value if db.query(User).count() == 0 else Role.SOC_ANALYST.value
    try:
        pw_hash = hash_password(body.password)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e))
    user = User(name=body.name.strip(), email=email, password_hash=pw_hash, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    audit(db, user_id=user.id, action="user.register", resource="user", resource_id=user.id,
          meta={"role": role})
    db.commit()
    return user


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.query(User).filter(func.lower(User.email) == email).first()
    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    token = create_access_token(subject=str(user.id), role=user.role)
    return TokenOut(access_token=token)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
