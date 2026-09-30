"""
SentinelGate — Authentication & RBAC Dependencies
==================================================
FastAPI route dependencies for:
- Bearer token extraction and cryptographic verification
- Revocation checking against Redis
- RBAC role enforcement (ADMIN, ANALYST, USER)
- Updating GatewayContext with authenticated user details
"""
from __future__ import annotations

from typing import Callable, Sequence

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.service import decode_jwt_token, is_token_revoked
from backend.database.models import User
from backend.database.session import get_db
from backend.schemas.auth import TokenPayload
from backend.schemas.context import GatewayContext, UserContext

security_bearer = HTTPBearer(auto_error=False)


async def get_current_token_payload(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
) -> TokenPayload:
    """
    Validate Bearer token from request:
    1. Check presence -> 401
    2. Decode & verify signature + expiry -> 401
    3. Check token type is 'access' -> 401
    4. Check Redis jti revocation -> 401
    5. Attach UserContext to GatewayContext in request.state
    """
    ctx: GatewayContext | None = getattr(request.state, "gateway_context", None)

    if not credentials or not credentials.credentials:
        if ctx:
            ctx.add_risk(5)  # Missing token on protected endpoint soft signal
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = credentials.credentials

    try:
        payload = decode_jwt_token(raw_token)
    except jwt.ExpiredSignatureError:
        if ctx:
            ctx.add_risk(10)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        if ctx:
            ctx.add_risk(10)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token signature or claims",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.type != "access":
        if ctx:
            ctx.add_risk(10)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token must be an access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if await is_token_revoked(payload.jti):
        if ctx:
            ctx.add_risk(30)  # Revoked token reuse is high risk signal
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Attach UserContext to GatewayContext
    user_ctx = UserContext(
        user_id=payload.sub,
        username=payload.username,
        role=payload.role,
    )
    if ctx:
        ctx.authenticated_user = user_ctx

    return payload


async def get_current_user(
    payload: TokenPayload = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Retrieve active user record from database matching token payload.
    """
    stmt = select(User).where(User.id == payload.sub)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


def require_roles(allowed_roles: Sequence[str]) -> Callable[..., User]:
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces that current user role matches one of allowed_roles.
    """
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: required role is one of {list(allowed_roles)} (current: {user.role})",
            )
        return user

    return role_checker


# Convenient RBAC dependencies
require_admin = require_roles(["ADMIN"])
require_analyst_or_admin = require_roles(["ADMIN", "ANALYST"])
require_user = require_roles(["ADMIN", "ANALYST", "USER"])
