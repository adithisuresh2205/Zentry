"""
SentinelGate — JWT & Password Security Service
==============================================
Cryptographic token generation, validation, password hashing via bcrypt,
and Redis token revocation (jti blocklist).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import uuid4

import bcrypt
import jwt

from backend.cache.redis_client import get_redis
from backend.config import get_settings
from backend.schemas.auth import TokenPayload


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def create_jwt_token(
    user_id: str,
    username: str,
    role: Literal["ADMIN", "ANALYST", "USER"],
    token_type: Literal["access", "refresh"],
    expires_delta: timedelta,
) -> tuple[str, str]:
    """
    Generate a signed JWT token and return (token, jti).
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp = now + expires_delta
    jti = str(uuid4())

    payload: dict[str, Any] = {
        "sub": user_id,
        "username": username,
        "role": role,
        "jti": jti,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token, jti


def decode_jwt_token(token: str) -> TokenPayload:
    """
    Decode and cryptographically verify a JWT token.
    Raises jwt.PyJWTError on invalid signature, expired, or malformed claims.
    """
    settings = get_settings()
    decoded = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["sub", "username", "role", "jti", "type", "iat", "exp"]},
    )
    return TokenPayload.model_validate(decoded)


# In-memory revocation fallback if Redis is uninitialized or offline
_in_memory_revoked: set[str] = set()


async def revoke_token(jti: str, ttl_seconds: int) -> None:
    """
    Add a token's jti to the Redis revocation blocklist with a TTL.
    Falls back to in-memory set if Redis is unreachable.
    """
    try:
        redis = get_redis()
        # Set blocklist key with remaining token lifetime as TTL
        await redis.set(f"revoked_jti:{jti}", "revoked", ex=max(ttl_seconds, 60))
    except Exception:
        # Fallback to local memory if Redis is not running
        _in_memory_revoked.add(jti)


async def is_token_revoked(jti: str) -> bool:
    """
    Check if a token's jti has been revoked in Redis or fallback in-memory store.
    """
    if jti in _in_memory_revoked:
        return True
    try:
        redis = get_redis()
        val = await redis.get(f"revoked_jti:{jti}")
        return val is not None
    except Exception:
        return False
