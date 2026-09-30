"""
Phase 3 — Integration Tests: Rate Limiting & Brute-Force Mitigation Pipeline
===========================================================================
Verifies end-to-end HTTP behavior:
1. Rate limit enforcement (HTTP 429 Too Many Requests when exceeding tier threshold)
2. Brute-force detection via repeated failed POST /auth/login calls
3. Escalation to IP block (HTTP 403 Forbidden on subsequent requests)
4. Counter reset on successful POST /auth/login
5. Security headers and correlation IDs present on rate-limited & blocked responses
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.service import hash_password
from backend.database.models import User
from backend.rate_limiter.ip_blocklist import is_ip_blocked, unblock_ip


class TestRateLimitingIntegration:
    """End-to-end integration tests for rate limiting through the gateway."""

    async def test_auth_login_rate_limiting(
        self, async_client: AsyncClient
    ) -> None:
        """
        /auth/login has a strict limit (e.g. 10 req/min in settings or test limit).
        Exceeding it must yield HTTP 429.
        """
        # Consume requests up to the limit
        blocked_seen = False
        for i in range(25):
            res = await async_client.post(
                "/auth/login",
                json={"username": f"nonexistent_{i}", "password": "wrongpassword"},
            )
            if res.status_code == 429:
                blocked_seen = True
                data = res.json()
                assert data["status"] == "blocked"
                assert "Rate limit" in data["message"]
                assert "X-Request-ID" in res.headers
                assert res.headers.get("X-Frame-Options") == "DENY"
                break

        assert blocked_seen is True, "Expected HTTP 429 rate limit rejection"


class TestBruteForceMitigationIntegration:
    """End-to-end integration tests for brute-force tracking & auto-blocking."""

    async def test_brute_force_triggers_ip_block(
        self, async_client: AsyncClient, test_db: AsyncSession
    ) -> None:
        """
        10 consecutive failed logins from the same client must trigger an IP block.
        Subsequent requests to ANY endpoint from that client must return HTTP 403.
        """
        # 1. Create legitimate user
        user = User(
            username="target_victim",
            password_hash=hash_password("ValidPassword123!"),
            role="USER",
            is_active=True,
        )
        test_db.add(user)
        await test_db.commit()

        # Clean up any leftover blocks for test client IP
        await unblock_ip("127.0.0.1")

        # 2. Fire 10 failed login attempts with wrong password
        for attempt in range(10):
            resp = await async_client.post(
                "/auth/login",
                json={"username": "target_victim", "password": "WrongPassword!"},
            )
            # Up until block, will be 401 or 429
            assert resp.status_code in (401, 429)

        # 3. Verify that the IP is now blocked
        blocked, reason = await is_ip_blocked("127.0.0.1")
        assert blocked is True

        # 4. Subsequent requests from this client must now be blocked with HTTP 403
        subsequent_resp = await async_client.get("/auth/me")
        assert subsequent_resp.status_code == 403
        data = subsequent_resp.json()
        assert data["status"] == "blocked"
        assert "IP address is blocked" in data["message"] or "Brute-force" in data["message"]

        # Clean up block so subsequent tests run smoothly
        await unblock_ip("127.0.0.1")

    async def test_successful_login_resets_counter(
        self, async_client: AsyncClient, test_db: AsyncSession
    ) -> None:
        """
        A successful login resets the failure counter, preventing a block.
        """
        user = User(
            username="clever_user",
            password_hash=hash_password("MySecretPassword123!"),
            role="USER",
            is_active=True,
        )
        test_db.add(user)
        await test_db.commit()

        await unblock_ip("127.0.0.1")

        # 3 failed logins
        for _ in range(3):
            await async_client.post(
                "/auth/login",
                json={"username": "clever_user", "password": "BadPassword"},
            )

        # 1 successful login resets counter
        success_resp = await async_client.post(
            "/auth/login",
            json={"username": "clever_user", "password": "MySecretPassword123!"},
        )
        assert success_resp.status_code == 200

        # Verify not blocked
        assert (await is_ip_blocked("127.0.0.1")) == (False, None)
