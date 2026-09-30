"""
Phase 3 — Unit Tests: Sliding-Window Rate Limiter
=================================================
Tests for:
- Sliding-window algorithm enforcement
- Atomic execution and concurrency safety
- IP independence and IPv6 /48 prefix aggregation
- Tier limits (/auth/login, /security, /api, global)
- Behavioral risk signals (near threshold +10, exceeded +20)
- GatewayPipeline rate limiting check
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from fakeredis.aioredis import FakeRedis

from backend.config import get_settings
from backend.network import get_rate_limit_ip_key
from backend.rate_limiter.limiter import (
    evaluate_rate_limit,
    get_endpoint_tier,
    rate_limiting_check,
)
from backend.schemas.context import GatewayContext


class TestSlidingWindowLimiter:
    """Tests for core sliding-window evaluation."""

    @pytest.mark.asyncio
    async def test_sliding_window_allows_within_limit(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.1.10"
        limit = 5
        window = 60

        for i in range(limit):
            allowed, count = await evaluate_rate_limit(ip, "test_tier", limit, window)
            assert allowed is True
            assert count == i + 1

    @pytest.mark.asyncio
    async def test_sliding_window_blocks_over_limit(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.1.11"
        limit = 3
        window = 60

        for _ in range(limit):
            allowed, _ = await evaluate_rate_limit(ip, "test_tier", limit, window)
            assert allowed is True

        # 4th request must be rejected
        allowed, count = await evaluate_rate_limit(ip, "test_tier", limit, window)
        assert allowed is False
        assert count == limit

    @pytest.mark.asyncio
    async def test_independent_ip_counters(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        limit = 2
        window = 60

        # Max out IP A
        await evaluate_rate_limit("10.0.0.1", "tier", limit, window)
        await evaluate_rate_limit("10.0.0.1", "tier", limit, window)
        allowed_a, _ = await evaluate_rate_limit("10.0.0.1", "tier", limit, window)
        assert allowed_a is False

        # IP B should still be fresh and allowed
        allowed_b, count_b = await evaluate_rate_limit("10.0.0.2", "tier", limit, window)
        assert allowed_b is True
        assert count_b == 1

    @pytest.mark.asyncio
    async def test_ipv6_prefix_aggregation(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Two different IPv6 addresses belonging to the same /48 prefix
        must share the same rate-limiting counter (loophole 15).
        """
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ipv6_host_1 = "2001:db8:abcd:0001::1"
        ipv6_host_2 = "2001:db8:abcd:ffff::99"
        ipv6_other_prefix = "2001:db8:eeee:0001::1"

        key1 = get_rate_limit_ip_key(ipv6_host_1)
        key2 = get_rate_limit_ip_key(ipv6_host_2)
        key_other = get_rate_limit_ip_key(ipv6_other_prefix)

        assert key1 == key2, "Hosts in the same /48 prefix must map to the same rate limit key"
        assert key1 != key_other, "Hosts in different /48 prefixes must have distinct keys"

        limit = 2
        window = 60

        await evaluate_rate_limit(key1, "tier", limit, window)
        await evaluate_rate_limit(key2, "tier", limit, window)

        # 3rd request from host 1 or host 2 must be blocked
        allowed_blocked, _ = await evaluate_rate_limit(key1, "tier", limit, window)
        assert allowed_blocked is False

        # Other prefix is still allowed
        allowed_other, _ = await evaluate_rate_limit(key_other, "tier", limit, window)
        assert allowed_other is True

    @pytest.mark.asyncio
    async def test_concurrent_requests_dont_race(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        Simulate concurrent requests from the same IP to ensure atomic enforcement (loophole 4).
        """
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "172.16.50.1"
        limit = 10
        window = 60

        async def make_req() -> tuple[bool, int]:
            return await evaluate_rate_limit(ip, "concurrency_tier", limit, window)

        results = await asyncio.gather(*(make_req() for _ in range(20)))
        allowed_count = sum(1 for allowed, _ in results if allowed)
        blocked_count = sum(1 for allowed, _ in results if not allowed)

        assert allowed_count == limit
        assert blocked_count == 10


class TestRateLimitingCheck:
    """Tests for the GatewayPipeline check callable."""

    def test_get_endpoint_tier_matching(self) -> None:
        assert get_endpoint_tier("/auth/login")[0] == "auth"
        assert get_endpoint_tier("/security/events")[0] == "security"
        assert get_endpoint_tier("/api/products")[0] == "api"
        assert get_endpoint_tier("/other/page")[0] == "global"

    @pytest.mark.asyncio
    async def test_check_allowed_low_usage(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ctx = GatewayContext(client_ip="192.168.10.5", method="GET", path="/api/items")
        result = await rate_limiting_check(ctx)
        assert result.passed is True
        assert result.risk_delta == 0

    @pytest.mark.asyncio
    async def test_check_near_threshold_adds_risk(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        # /auth/login limit is 10, 80% threshold is 8
        ip = "192.168.10.6"
        for _ in range(7):
            await evaluate_rate_limit(ip, "auth", limit=10, window_seconds=60)

        ctx = GatewayContext(client_ip=ip, method="POST", path="/auth/login")
        result = await rate_limiting_check(ctx)
        assert result.passed is True
        assert result.risk_delta == 10
        assert result.threat is not None
        assert result.threat.rule_id == "RATE_LIMIT_NEAR_THRESHOLD"

    @pytest.mark.asyncio
    async def test_check_exceeded_blocks_with_429(
        self, mock_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        ip = "192.168.10.7"
        # Consume all 10 requests for auth tier
        for _ in range(10):
            await evaluate_rate_limit(ip, "auth", limit=10, window_seconds=60)

        ctx = GatewayContext(client_ip=ip, method="POST", path="/auth/login")
        result = await rate_limiting_check(ctx)
        assert result.passed is False
        assert result.status_code == 429
        assert result.risk_delta == 20
        assert "Rate limit" in (result.block_reason or "")
        assert result.threat is not None
        assert result.threat.rule_id == "RATE_LIMIT_EXCEEDED"
