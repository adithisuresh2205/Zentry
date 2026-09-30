"""
SentinelGate — Redis Client
=============================
Provides a shared async Redis connection pool.
Used by: rate limiter, brute-force detector, token blocklist (Phases 2–3).
This module exists in Phase 0 to satisfy the lifespan import.
"""
from __future__ import annotations

import structlog
from redis.asyncio import Redis, from_url

from backend.config import get_settings

log = structlog.get_logger(__name__)

# Module-level Redis singleton (set during init_redis)
_redis: Redis | None = None  # type: ignore[type-arg]


async def init_redis() -> None:
    """
    Initialise the Redis connection pool.
    Called once at application startup.
    """
    global _redis
    settings = get_settings()

    _redis = from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=50,
    )

    try:
        # Verify connection
        await _redis.ping()
        log.info("sentinelgate.redis.connected", url=_mask_redis_url(settings.redis_url))
    except Exception as exc:
        if not settings.is_production:
            from fakeredis.aioredis import FakeRedis  # noqa: PLC0415
            _redis = FakeRedis(decode_responses=True)
            log.warn(
                "sentinelgate.redis.fallback_fakeredis",
                message="External Redis offline. Using in-memory FakeRedis for local development.",
                error=str(exc),
            )
        else:
            raise


async def close_redis() -> None:
    """Close the Redis connection pool. Called at application shutdown."""
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None
        log.info("sentinelgate.redis.disconnected")


def get_redis() -> Redis:  # type: ignore[type-arg]
    """
    Return the shared Redis client.

    Usage:
        redis = get_redis()
        await redis.set("key", "value", ex=60)

    Raises:
        RuntimeError: if called before init_redis().
    """
    if _redis is None:
        raise RuntimeError("Redis not initialised. Call init_redis() first.")
    return _redis


def _mask_redis_url(url: str) -> str:
    """Mask the password in a Redis URL for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse  # noqa: PLC0415
        parsed = urlparse(url)
        if parsed.password:
            masked = parsed._replace(
                netloc=parsed.netloc.replace(parsed.password, "***")
            )
            return urlunparse(masked)
    except Exception:
        pass
    return "<redis-url>"
