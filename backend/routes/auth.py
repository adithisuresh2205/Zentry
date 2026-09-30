"""
SentinelGate — Authentication Routes
====================================
Public endpoints:
- POST /auth/register: Create new user account with hashed password
- POST /auth/login: Validate credentials, issue access & refresh tokens
- POST /auth/refresh: Validate refresh token, issue new access token
- POST /auth/logout: Revoke refresh & access tokens via Redis jti blocklist
- GET  /auth/me: Return current authenticated user profile
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import get_current_token_payload, get_current_user
from backend.auth.service import (
    create_jwt_token,
    decode_jwt_token,
    hash_password,
    is_token_revoked,
    revoke_token,
    verify_password,
)
from backend.config import get_settings
from backend.database.models import User
from backend.database.session import get_db
from backend.rate_limiter import record_login_failure, record_login_success
from backend.schemas.auth import (
    RefreshTokenRequest,
    TokenPayload,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from backend.schemas.context import GatewayContext

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(
    req: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Create a new user with hashed password."""
    existing_stmt = select(User).where(User.username == req.username)
    result = await db.execute(existing_stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{req.username}' is already taken",
        )

    user = User(
        username=req.username,
        password_hash=hash_password(req.password),
        role=req.role,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and receive JWT tokens",
)
async def login(
    req: UserLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validate user credentials and return access + refresh tokens."""
    settings = get_settings()
    ctx: GatewayContext | None = getattr(request.state, "gateway_context", None)
    client_ip = ctx.client_ip if ctx else (request.client.host if request.client else "127.0.0.1")

    stmt = select(User).where(User.username == req.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(req.password, user.password_hash):
        count, risk_delta, is_blocked = await record_login_failure(client_ip, req.username)
        if ctx:
            ctx.add_risk(max(20, risk_delta))  # Failed login signal + brute force escalation
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    # Reset brute force counter on successful authentication
    await record_login_success(client_ip, req.username)

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    # Generate tokens
    access_delta = timedelta(minutes=settings.access_token_expire_minutes)
    refresh_delta = timedelta(days=settings.refresh_token_expire_days)

    access_token, _ = create_jwt_token(
        user_id=user.id,
        username=user.username,
        role=user.role,  # type: ignore[arg-type]
        token_type="access",
        expires_delta=access_delta,
    )
    refresh_token, _ = create_jwt_token(
        user_id=user.id,
        username=user.username,
        role=user.role,  # type: ignore[arg-type]
        token_type="refresh",
        expires_delta=refresh_delta,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_seconds,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using refresh token",
)
async def refresh(
    req: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validate refresh token and issue a new access token."""
    settings = get_settings()

    try:
        payload = decode_jwt_token(req.refresh_token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if payload.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provided token is not a refresh token",
        )

    if await is_token_revoked(payload.jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    stmt = select(User).where(User.id == payload.sub)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated",
        )

    access_delta = timedelta(minutes=settings.access_token_expire_minutes)
    new_access_token, _ = create_jwt_token(
        user_id=user.id,
        username=user.username,
        role=user.role,  # type: ignore[arg-type]
        token_type="access",
        expires_delta=access_delta,
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=req.refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_seconds,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout and revoke active tokens",
)
async def logout(
    req: RefreshTokenRequest | None = Body(default=None),
    payload: TokenPayload = Depends(get_current_token_payload),
) -> dict[str, str]:
    """
    Revoke both current access token and optional refresh token in Redis.
    """
    settings = get_settings()

    # Revoke the access token used to authenticate logout
    await revoke_token(payload.jti, ttl_seconds=settings.access_token_expire_seconds)

    # If refresh token supplied, revoke it too
    if req and req.refresh_token:
        try:
            refresh_payload = decode_jwt_token(req.refresh_token)
            await revoke_token(
                refresh_payload.jti,
                ttl_seconds=settings.refresh_token_expire_seconds,
            )
        except Exception:
            pass

    return {"status": "logged_out", "message": "Tokens revoked successfully"}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(user: User = Depends(get_current_user)) -> UserResponse:
    """Return profile of authenticated user."""
    return UserResponse.model_validate(user)
