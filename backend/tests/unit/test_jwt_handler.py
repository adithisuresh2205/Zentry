"""
Phase 2 — Unit Tests: JWT & Cryptographic Security Service
===========================================================
Tests for bcrypt password hashing, JWT creation, claim structure,
signature verification, token expiration, tampering rejection,
and token revocation via Redis / fallback in-memory store.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

import jwt
import pytest
from fakeredis.aioredis import FakeRedis

from backend.auth.service import (
    create_jwt_token,
    decode_jwt_token,
    hash_password,
    is_token_revoked,
    revoke_token,
    verify_password,
)
from backend.config import get_settings
from backend.schemas.auth import TokenPayload


class TestPasswordHashing:
    """Tests for bcrypt password hashing and verification."""

    def test_hash_password_produces_bcrypt_format(self) -> None:
        pwd = "SuperSecretPassword123!"
        hashed = hash_password(pwd)
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
        assert len(hashed) >= 59

    def test_hash_password_salts_distinctly(self) -> None:
        pwd = "IdenticalPassword123!"
        hash1 = hash_password(pwd)
        hash2 = hash_password(pwd)
        assert hash1 != hash2, "Different salts must produce different hashes"

    def test_verify_password_correct(self) -> None:
        pwd = "CorrectPassword123!"
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True

    def test_verify_password_incorrect(self) -> None:
        pwd = "CorrectPassword123!"
        hashed = hash_password(pwd)
        assert verify_password("WrongPassword123!", hashed) is False

    def test_verify_password_empty_strings(self) -> None:
        assert verify_password("", "") is False

    def test_verify_password_malformed_hash_does_not_crash(self) -> None:
        assert verify_password("AnyPassword123!", "not-a-valid-bcrypt-hash") is False


class TestJWTCreationAndDecoding:
    """Tests for JWT token creation, claim structures, and decoding."""

    def test_create_and_decode_access_token(self) -> None:
        token, jti = create_jwt_token(
            user_id="user-1234",
            username="alice",
            role="ADMIN",
            token_type="access",
            expires_delta=timedelta(minutes=15),
        )

        assert isinstance(token, str)
        assert len(token) > 20
        assert isinstance(jti, str)
        assert len(jti) > 10

        payload = decode_jwt_token(token)
        assert isinstance(payload, TokenPayload)
        assert payload.sub == "user-1234"
        assert payload.username == "alice"
        assert payload.role == "ADMIN"
        assert payload.type == "access"
        assert payload.jti == jti
        assert payload.exp > payload.iat

    def test_create_and_decode_refresh_token(self) -> None:
        token, jti = create_jwt_token(
            user_id="user-5678",
            username="bob",
            role="USER",
            token_type="refresh",
            expires_delta=timedelta(days=7),
        )
        payload = decode_jwt_token(token)
        assert payload.sub == "user-5678"
        assert payload.type == "refresh"
        assert payload.jti == jti

    def test_decode_expired_token_raises_expired_signature_error(self) -> None:
        token, _ = create_jwt_token(
            user_id="user-expired",
            username="eve",
            role="USER",
            token_type="access",
            expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
        )

        with pytest.raises(jwt.ExpiredSignatureError):
            decode_jwt_token(token)

    def test_decode_token_with_tampered_signature_raises_jwt_error(self) -> None:
        token, _ = create_jwt_token(
            user_id="user-tampered",
            username="charlie",
            role="USER",
            token_type="access",
            expires_delta=timedelta(minutes=15),
        )

        # Alter the last 4 characters of the token
        tampered_token = token[:-4] + "xxxx"
        with pytest.raises(jwt.PyJWTError):
            decode_jwt_token(tampered_token)

    def test_decode_token_signed_with_wrong_secret_raises_jwt_error(self) -> None:
        settings = get_settings()
        wrong_secret = "b" * 64
        token = jwt.encode(
            {
                "sub": "user-wrong",
                "username": "dave",
                "role": "USER",
                "jti": "some-jti",
                "type": "access",
                "iat": 1000,
                "exp": 9999999999,
            },
            wrong_secret,
            algorithm=settings.jwt_algorithm,
        )

        with pytest.raises(jwt.PyJWTError):
            decode_jwt_token(token)

    def test_decode_token_missing_required_claims_raises_jwt_error(self) -> None:
        settings = get_settings()
        # Omit 'jti' and 'role'
        incomplete_token = jwt.encode(
            {
                "sub": "user-missing-claims",
                "username": "mallory",
                "type": "access",
                "iat": 1000,
                "exp": 9999999999,
            },
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )

        with pytest.raises(jwt.PyJWTError):
            decode_jwt_token(incomplete_token)


class TestTokenRevocation:
    """Tests for token revocation via Redis and fallback in-memory store."""

    @pytest.mark.asyncio
    async def test_token_revocation_with_redis(self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        jti = "test-jti-redis-12345"
        assert await is_token_revoked(jti) is False

        await revoke_token(jti, ttl_seconds=300)
        assert await is_token_revoked(jti) is True

    @pytest.mark.asyncio
    async def test_token_revocation_in_memory_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate Redis offline / RuntimeError on get_redis
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", None)

        jti = "test-jti-fallback-99999"
        assert await is_token_revoked(jti) is False

        await revoke_token(jti, ttl_seconds=300)
        assert await is_token_revoked(jti) is True
