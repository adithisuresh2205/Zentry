"""
SentinelGate — Sliding-Window Rate Limiter
===========================================
High-performance sliding-window rate limiter using Redis ZSET with atomic Lua script.
Concurrency-safe (zero TOCTOU race conditions, loophole 4).
Supports:
- Distinct rate tiers (Global, /auth/login, /security/*, /api/*)
- IPv6 /48 prefix aggregation (loophole 15)
- Behavioral risk scoring (near threshold: +10 risk, exceeded: +20 risk)
- In-memory lock-guarded fallback for offline Redis / local testing
"""
from __future__ import annotations

import asyncio
import time
from uuid import uuid4

import structlog

from backend.cache.redis_client import get_redis
from backend.config import get_settings
from backend.network import get_rate_limit_ip_key
from backend.schemas.context import CheckResult, GatewayContext, ThreatMatch

log = structlog.get_logger(__name__)

# Atomic Redis Lua script for sliding window rate limiting
SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

local clear_before = now - window
redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window) + 1)
    return {1, current_count + 1}
else
    return {0, current_count}
end
"""

# In-memory sliding window fallback: key -> list of float timestamps
_in_memory_windows: dict[str, list[float]] = {}
_in_memory_lock = asyncio.Lock()


def get_endpoint_tier(path: str) -> tuple[str, int, int]:
    """
    Return (tier_name, limit, window_seconds) based on request path.
    """
    settings = get_settings()
    normalized_path = path.rstrip("/")

    if normalized_path == "/auth/login":
        return (
            "auth",
            settings.rate_limit_auth_requests,
            settings.rate_limit_auth_window_seconds,
        )
    elif normalized_path.startswith("/security"):
        return (
            "security",
            settings.rate_limit_security_requests,
            settings.rate_limit_window_seconds,
        )
    elif normalized_path.startswith("/api"):
        return (
            "api",
            settings.rate_limit_api_requests,
            settings.rate_limit_window_seconds,
        )
    else:
        return (
            "global",
            settings.rate_limit_requests,
            settings.rate_limit_window_seconds,
        )


async def evaluate_rate_limit(
    ip_key: str,
    tier: str,
    limit: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """
    Atomically record request and check if within rate limit.
    Uses Redis pipeline transaction (MULTI/EXEC) for zero TOCTOU race conditions.
    Returns (allowed: bool, current_count: int).
    """
    now = time.time()
    redis_key = f"rate:{ip_key}:{tier}"
    member = f"{now}:{uuid4().hex[:8]}"
    threshold = now - window_seconds

    # 1. Try Redis with atomic MULTI/EXEC pipeline transaction
    try:
        redis = get_redis()
        pipe = redis.pipeline(transaction=True)
        pipe.zremrangebyscore(redis_key, 0, threshold)
        pipe.zcard(redis_key)
        pipe.zadd(redis_key, {member: now})
        pipe.expire(redis_key, window_seconds + 1)
        res = await pipe.execute()
        count = int(res[1]) + 1
        if count <= limit:
            return True, count
        else:
            await redis.zrem(redis_key, member)
            return False, int(res[1])
    except Exception as e:
        log.debug("rate_limiter.redis_fallback", error=str(e))

    # 2. Concurrency-safe in-memory fallback
    async with _in_memory_lock:
        timestamps = _in_memory_windows.get(redis_key, [])
        # Evict timestamps older than sliding window
        timestamps = [ts for ts in timestamps if ts > threshold]

        if len(timestamps) < limit:
            timestamps.append(now)
            _in_memory_windows[redis_key] = timestamps
            return True, len(timestamps)
        else:
            _in_memory_windows[redis_key] = timestamps
            return False, len(timestamps)


def reset_in_memory_rate_limits() -> None:
    """Clear all in-memory sliding windows (for test isolation)."""
    _in_memory_windows.clear()


async def rate_limiting_check(ctx: GatewayContext) -> CheckResult:
    """
    GatewayPipeline security check:
    Enforces per-tier sliding window rate limits.
    - Exceeded limit: blocks with HTTP 429 and adds +20 risk
    - Near threshold (>= 80% of limit): allows but adds +10 risk
    """
    tier, limit, window = get_endpoint_tier(ctx.path)
    ip_key = get_rate_limit_ip_key(ctx.client_ip)

    allowed, current_count = await evaluate_rate_limit(
        ip_key=ip_key,
        tier=tier,
        limit=limit,
        window_seconds=window,
    )

    if not allowed:
        threat = ThreatMatch(
            rule_id="RATE_LIMIT_EXCEEDED",
            category="RATE_LIMIT",
            severity="HIGH",
            risk_delta=20,
            details=f"Rate limit exceeded for tier '{tier}' ({current_count}/{limit} req in {window}s)",
            target=f"tier:{tier}",
        )
        return CheckResult(
            passed=False,
            risk_delta=20,
            threat=threat,
            block_reason=f"Too Many Requests: Rate limit of {limit} req/{window}s exceeded for {tier}",
            status_code=429,
        )

    # Near threshold detection (>= 80% limit consumed)
    if current_count >= max(1, int(limit * 0.8)):
        threat = ThreatMatch(
            rule_id="RATE_LIMIT_NEAR_THRESHOLD",
            category="RATE_LIMIT",
            severity="MEDIUM",
            risk_delta=10,
            details=f"Rate limit near threshold for tier '{tier}' ({current_count}/{limit})",
            target=f"tier:{tier}",
        )
        return CheckResult(
            passed=True,
            risk_delta=10,
            threat=threat,
        )

    return CheckResult(passed=True)
