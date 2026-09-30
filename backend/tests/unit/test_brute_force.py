"""
Phase 3 — Unit Tests: Brute-Force Detection & IP Blocklist Store
===============================================================
Tests for:
- Progressive threshold escalation (5 failures -> +20 risk, 10 -> block +40, 20 -> extended +60)
- Reset of failed attempts on successful login
- Persistent IP blocklist store across restarts / cache clear (loophole 14)
- Unblock mechanism
- GatewayPipeline IP blocklist check
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fakeredis.aioredis import FakeRedis
from sqlalchemy.ext.asyncio import AsyncSession

from backend.rate_limiter.brute_force import (
    get_failed_attempts,
    record_login_failure,
    record_login_success,
)
from backend.rate_limiter.ip_blocklist import (
    block_ip,
    ip_blocklist_check,
    is_ip_blocked,
    unblock_ip,
)
from backend.schemas.context import GatewayContext


class TestBruteForceEscalation:
    """Tests for login failure counter and threshold escalation."""

    @pytest.mark.asyncio
    async def test_below_threshold_no_risk_no_block(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.200.1"
        username = "target_user"

        for i in range(4):
            count, risk_delta, is_blocked = await record_login_failure(ip, username)
            assert count == i + 1
            assert risk_delta == 0
            assert is_blocked is False

        assert await is_ip_blocked(ip) == (False, None)

    @pytest.mark.asyncio
    async def test_warn_threshold_adds_risk(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.200.2"
        username = "target_user"

        # 5th attempt triggers warning
        for _ in range(4):
            await record_login_failure(ip, username)

        count, risk_delta, is_blocked = await record_login_failure(ip, username)
        assert count == 5
        assert risk_delta == 20
        assert is_blocked is False
        assert await is_ip_blocked(ip) == (False, None)

    @pytest.mark.asyncio
    async def test_block_threshold_triggers_temporary_block(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch, test_db: AsyncSession
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.200.3"
        username = "victim_user"

        # Advance to 9 attempts
        for _ in range(9):
            await record_login_failure(ip, username)

        # 10th attempt triggers temporary block
        count, risk_delta, is_blocked = await record_login_failure(ip, username)
        assert count == 10
        assert risk_delta == 40
        assert is_blocked is True

        # Verify IP is marked blocked
        blocked, reason = await is_ip_blocked(ip)
        assert blocked is True
        assert "Brute-force" in (reason or "")

    @pytest.mark.asyncio
    async def test_extended_block_threshold(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch, test_db: AsyncSession
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.200.4"
        username = "victim_user_2"

        # Advance to 19 attempts
        for _ in range(19):
            await record_login_failure(ip, username)

        # 20th attempt triggers extended block (+60 risk)
        count, risk_delta, is_blocked = await record_login_failure(ip, username)
        assert count == 20
        assert risk_delta == 60
        assert is_blocked is True

    @pytest.mark.asyncio
    async def test_reset_on_successful_login(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.200.5"
        username = "legit_user"

        await record_login_failure(ip, username)
        await record_login_failure(ip, username)
        assert await get_failed_attempts(ip, username) == 2

        await record_login_success(ip, username)
        assert await get_failed_attempts(ip, username) == 0


class TestIPBlocklistStore:
    """Tests for persistent IP blocklist operations."""

    @pytest.mark.asyncio
    async def test_manual_block_and_unblock(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch, test_db: AsyncSession
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "10.50.0.1"
        assert await is_ip_blocked(ip) == (False, None)

        await block_ip(ip, reason="Admin manual block", ttl_seconds=3600)
        blocked, reason = await is_ip_blocked(ip)
        assert blocked is True
        assert reason == "Admin manual block"

        # Unblock
        unblocked = await unblock_ip(ip)
        assert unblocked is True
        assert await is_ip_blocked(ip) == (False, None)

    @pytest.mark.asyncio
    async def test_persistence_across_redis_flush(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch, test_db: AsyncSession
    ) -> None:
        """
        Verify that database storage preserves IP blocks even if Redis cache is flushed (loophole 14).
        """
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "10.60.0.99"
        await block_ip(ip, reason="Persistent threat", ttl_seconds=1800)
        assert (await is_ip_blocked(ip))[0] is True

        # Simulate Redis restart / cache flush
        await mock_redis.flushall()

        # Should recover from database layer
        blocked, reason = await is_ip_blocked(ip)
        assert blocked is True
        assert reason == "Persistent threat"

    @pytest.mark.asyncio
    async def test_pipeline_block_check_rejection(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch, test_db: AsyncSession
    ) -> None:
        """
        GatewayPipeline security check rejects requests from blocked IPs with 403.
        """
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        blocked_ip = "198.51.100.250"
        await block_ip(blocked_ip, reason="Attacker IP", ttl_seconds=600)

        # Context from blocked IP
        ctx = GatewayContext(client_ip=blocked_ip, method="GET", path="/api/data")
        result = await ip_blocklist_check(ctx)

        assert result.passed is False
        assert result.status_code == 403
        assert result.risk_delta == 50
        assert "Attacker IP" in (result.block_reason or "")
        assert result.threat is not None
        assert result.threat.rule_id == "IP_BLOCKLIST"

        # Clean IP passes
        clean_ctx = GatewayContext(client_ip="198.51.100.1", method="GET", path="/api/data")
        clean_result = await ip_blocklist_check(clean_ctx)
        assert clean_result.passed is True
