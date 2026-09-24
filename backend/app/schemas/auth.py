"""Auth + user schemas."""
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import ORMModel


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=72)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(ORMModel):
    id: int
    name: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class UserUpdate(BaseModel):
    role: str | None = Field(default=None, pattern="^(ADMIN|SOC_ANALYST)$")
    is_active: bool | None = None
