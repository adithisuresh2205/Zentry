"""
Phase 2 — Integration Tests: Authentication & RBAC Flow
========================================================
Comprehensive end-to-end integration tests for:
- User registration (success, duplicate check, validation)
- User login (valid credentials, invalid password, deactivated account)
- JWT access & refresh token lifecycle
- Token refresh endpoint & type enforcement
- Logout & revocation via Redis
- /auth/me user profile endpoint
- Role-Based Access Control (RBAC) enforcement across ADMIN, ANALYST, and USER roles
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi import APIRouter, Depends
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import (
    get_current_user,
    require_admin,
    require_analyst_or_admin,
    require_user,
)
from backend.auth.service import create_jwt_token, hash_password
from backend.database.models import User

# Test router to verify RBAC dependencies
rbac_test_router = APIRouter(prefix="/test/rbac")


@rbac_test_router.get("/admin-only")
async def admin_only_endpoint(user: User = Depends(require_admin)) -> dict[str, str]:
    return {"status": "ok", "role": user.role, "username": user.username}


@rbac_test_router.get("/analyst-or-admin")
async def analyst_or_admin_endpoint(user: User = Depends(require_analyst_or_admin)) -> dict[str, str]:
    return {"status": "ok", "role": user.role, "username": user.username}


@rbac_test_router.get("/user-or-above")
async def user_or_above_endpoint(user: User = Depends(require_user)) -> dict[str, str]:
    return {"status": "ok", "role": user.role, "username": user.username}


class TestUserRegistration:
    """Tests for POST /auth/register."""

    async def test_register_user_success(self, async_client: AsyncClient, test_db: AsyncSession) -> None:
        payload = {
            "username": "new_user_1",
            "password": "SecurePassword123!",
            "role": "USER",
        }
        response = await async_client.post("/auth/register", json=payload)
        assert response.status_code == 201

        data = response.json()
        assert data["username"] == "new_user_1"
        assert data["role"] == "USER"
        assert data["is_active"] is True
        assert "password" not in data
        assert "password_hash" not in data

        # Verify DB persisted record
        stmt = select(User).where(User.username == "new_user_1")
        result = await test_db.execute(stmt)
        user = result.scalar_one_or_none()
        assert user is not None
        assert user.password_hash != "SecurePassword123!"

    async def test_register_duplicate_username_conflict(self, async_client: AsyncClient) -> None:
        payload = {
            "username": "duplicate_user",
            "password": "SecurePassword123!",
            "role": "USER",
        }
        resp1 = await async_client.post("/auth/register", json=payload)
        assert resp1.status_code == 201

        resp2 = await async_client.post("/auth/register", json=payload)
        assert resp2.status_code == 409
        assert "already taken" in resp2.json()["detail"]

    async def test_register_validation_short_password(self, async_client: AsyncClient) -> None:
        payload = {
            "username": "short_pwd_user",
            "password": "123",  # min 8 chars required
            "role": "USER",
        }
        response = await async_client.post("/auth/register", json=payload)
        assert response.status_code == 422


class TestUserLogin:
    """Tests for POST /auth/login."""

    async def test_login_success(self, async_client: AsyncClient, test_db: AsyncSession) -> None:
        user = User(
            username="login_test_user",
            password_hash=hash_password("CorrectPass123!"),
            role="USER",
            is_active=True,
        )
        test_db.add(user)
        await test_db.commit()

        login_payload = {
            "username": "login_test_user",
            "password": "CorrectPass123!",
        }
        response = await async_client.post("/auth/login", json=login_payload)
        assert response.status_code == 200

        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["username"] == "login_test_user"
        assert data["role"] == "USER"
        assert data["expires_in"] > 0

    async def test_login_invalid_password(self, async_client: AsyncClient, test_db: AsyncSession) -> None:
        user = User(
            username="invalid_pwd_user",
            password_hash=hash_password("RealPassword123!"),
            role="USER",
            is_active=True,
        )
        test_db.add(user)
        await test_db.commit()

        response = await async_client.post(
            "/auth/login",
            json={"username": "invalid_pwd_user", "password": "WrongPassword123!"},
        )
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]

    async def test_login_unknown_user(self, async_client: AsyncClient) -> None:
        response = await async_client.post(
            "/auth/login",
            json={"username": "ghost_user", "password": "AnyPassword123!"},
        )
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]

    async def test_login_deactivated_user(self, async_client: AsyncClient, test_db: AsyncSession) -> None:
        user = User(
            username="deactivated_user",
            password_hash=hash_password("Pass123456!"),
            role="USER",
            is_active=False,
        )
        test_db.add(user)
        await test_db.commit()

        response = await async_client.post(
            "/auth/login",
            json={"username": "deactivated_user", "password": "Pass123456!"},
        )
        assert response.status_code == 403
        assert "deactivated" in response.json()["detail"].lower()


class TestTokenRefreshAndLogout:
    """Tests for POST /auth/refresh and POST /auth/logout."""

    async def test_refresh_token_success(self, async_client: AsyncClient, test_db: AsyncSession) -> None:
        user = User(
            username="refresh_user",
            password_hash=hash_password("Pass123456!"),
            role="USER",
            is_active=True,
        )
        test_db.add(user)
        await test_db.commit()
        await test_db.refresh(user)

        refresh_token, _ = create_jwt_token(
            user_id=user.id,
            username=user.username,
            role="USER",
            token_type="refresh",
            expires_delta=timedelta(days=7),
        )

        response = await async_client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["username"] == "refresh_user"

    async def test_refresh_using_access_token_rejected(self, async_client: AsyncClient, user_token: str) -> None:
        # Supplying an access token where refresh token is expected must fail
        response = await async_client.post(
            "/auth/refresh",
            json={"refresh_token": user_token},
        )
        assert response.status_code == 401
        assert "not a refresh token" in response.json()["detail"].lower()

    async def test_logout_revokes_tokens(
        self,
        async_client: AsyncClient,
        test_db: AsyncSession,
    ) -> None:
        user = User(
            username="logout_user",
            password_hash=hash_password("Pass123456!"),
            role="USER",
            is_active=True,
        )
        test_db.add(user)
        await test_db.commit()
        await test_db.refresh(user)

        access_token, _ = create_jwt_token(
            user_id=user.id,
            username=user.username,
            role="USER",
            token_type="access",
            expires_delta=timedelta(minutes=15),
        )
        refresh_token, _ = create_jwt_token(
            user_id=user.id,
            username=user.username,
            role="USER",
            token_type="refresh",
            expires_delta=timedelta(days=7),
        )

        headers = {"Authorization": f"Bearer {access_token}"}

        # 1. Access /auth/me -> 200
        resp1 = await async_client.get("/auth/me", headers=headers)
        assert resp1.status_code == 200

        # 2. Call /auth/logout with refresh_token in body
        logout_resp = await async_client.post(
            "/auth/logout",
            headers=headers,
            json={"refresh_token": refresh_token},
        )
        assert logout_resp.status_code == 200

        # 3. Access /auth/me with the revoked access token -> 401
        resp2 = await async_client.get("/auth/me", headers=headers)
        assert resp2.status_code == 401
        assert "revoked" in resp2.json()["detail"].lower()

        # 4. Attempt refresh with the revoked refresh token -> 401
        refresh_resp = await async_client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 401
        assert "revoked" in refresh_resp.json()["detail"].lower()


class TestUserProfileEndpoint:
    """Tests for GET /auth/me."""

    async def test_get_me_authenticated(self, async_client: AsyncClient, user_token: str) -> None:
        response = await async_client.get("/auth/me", headers={"Authorization": f"Bearer {user_token}"})
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "fixture_user"
        assert data["role"] == "USER"

    async def test_get_me_missing_token_returns_401(self, async_client: AsyncClient) -> None:
        response = await async_client.get("/auth/me")
        assert response.status_code == 401
        assert "missing" in response.json()["detail"].lower()

    async def test_get_me_expired_token_returns_401(self, async_client: AsyncClient) -> None:
        token, _ = create_jwt_token(
            user_id="any-id",
            username="test_expired",
            role="USER",
            token_type="access",
            expires_delta=timedelta(seconds=-60),
        )
        response = await async_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert "expired" in response.json()["detail"].lower()


class TestRBACPermissions:
    """Tests verifying role-based access control (ADMIN, ANALYST, USER)."""

    @pytest.fixture(autouse=True)
    def register_rbac_routes(self) -> None:
        from backend.main import create_app
        # Routes registered via dependency test
        pass

    async def test_admin_can_access_admin_route(
        self,
        async_client: AsyncClient,
        admin_token: str,
    ) -> None:
        # Include rbac_test_router dynamically on client's underlying app
        app = async_client._transport.app  # type: ignore[attr-defined]
        if not any(r.path == "/test/rbac/admin-only" for r in app.routes):
            app.include_router(rbac_test_router)

        response = await async_client.get(
            "/test/rbac/admin-only",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["role"] == "ADMIN"

    async def test_user_forbidden_from_admin_route(
        self,
        async_client: AsyncClient,
        user_token: str,
    ) -> None:
        app = async_client._transport.app  # type: ignore[attr-defined]
        if not any(r.path == "/test/rbac/admin-only" for r in app.routes):
            app.include_router(rbac_test_router)

        response = await async_client.get(
            "/test/rbac/admin-only",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    async def test_analyst_can_access_analyst_route_but_not_admin(
        self,
        async_client: AsyncClient,
        analyst_token: str,
    ) -> None:
        app = async_client._transport.app  # type: ignore[attr-defined]
        if not any(r.path == "/test/rbac/analyst-or-admin" for r in app.routes):
            app.include_router(rbac_test_router)

        # Analyst on Analyst/Admin endpoint -> 200 OK
        resp_allowed = await async_client.get(
            "/test/rbac/analyst-or-admin",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp_allowed.status_code == 200
        assert resp_allowed.json()["role"] == "ANALYST"

        # Analyst on Admin-only endpoint -> 403 Forbidden
        resp_denied = await async_client.get(
            "/test/rbac/admin-only",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp_denied.status_code == 403
