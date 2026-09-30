"""
SentinelGate — Authentication & User Request/Response Schemas
=============================================================
Pydantic schemas for login, register, token response, user representation,
and token payload verification.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class UserRegisterRequest(BaseModel):
    """Payload for registering a new user."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: Literal["USER", "ANALYST", "ADMIN"] = "USER"


class UserLoginRequest(BaseModel):
    """Payload for user login."""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class RefreshTokenRequest(BaseModel):
    """Payload for token refresh."""
    refresh_token: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """Response returned upon successful authentication."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    username: str
    role: str


class UserResponse(BaseModel):
    """Public user information returned by endpoints."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None


class TokenPayload(BaseModel):
    """Decoded JWT claims."""
    sub: str          # user_id
    username: str
    role: Literal["ADMIN", "ANALYST", "USER"]
    jti: str          # unique token ID
    type: Literal["access", "refresh"]
    iat: int
    exp: int
