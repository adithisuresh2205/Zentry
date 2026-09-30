"""
SentinelGate — Brute-Force Detection & Mitigation
=================================================
Monitors repeated failed authentication attempts per (IP, username) combination.
Threshold escalation:
- 5–9 failures: +20 risk score (WARN)
- 10–19 failures: +40 risk score, temporary 15-minute IP block
- 20+ failures: +60 risk score, extended 1-hour IP block
Tied directly to the persistent IP blocklist (closes loophole 5).
"""
from __future__ import annotations

import asyncio
import time

import structlog

from backend.cache.redis_client import get_redis
from backend.config import get_settings
from backend.network import get_rate_limit_ip_key
from backend.rate_limiter.ip_blocklist import block_ip

log = structlog.get_logger(__name__)

# Fallback in-memory store: "bf:{ip}:{username}" -> (count, expire_epoch)
_in_memory_bf: dict[str, tuple[int, float]] = {}
_in_memory_bf_lock = asyncio.Lock()


async def record_login_failure(ip: str, username: str) -> tuple[int, int, bool]:
    """
    Record a failed login attempt for (ip, username).
    Returns:
        (fail_count: int, risk_delta: int, is_blocked: bool)
    """
    settings = get_settings()
    ip_key = get_rate_limit_ip_key(ip)
    clean_username = username.strip().lower()
    redis_key = f"bf:{ip_key}:{clean_username}"
    ttl = settings.brute_force_extended_ttl_seconds  # Keep counter alive for window

    count = 1

    # 1. Try Redis atomic INCR
    try:
        redis = get_redis()
        pipe = redis.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, ttl)
        results = await pipe.execute()
        count = int(results[0])
    except Exception:
        # 2. Concurrency-safe in-memory fallback
        async with _in_memory_bf_lock:
            now = time.time()
            existing_count, exp = _in_memory_bf.get(redis_key, (0, now + ttl))
            if now > exp:
                existing_count = 0
            count = existing_count + 1
            _in_memory_bf[redis_key] = (count, now + ttl)

    # 3. Evaluate escalation thresholds
    if count >= settings.brute_force_extended_threshold:
        block_duration = settings.brute_force_extended_ttl_seconds
        reason = f"Brute-force attack detected ({count} failed login attempts for '{clean_username}')"
        await block_ip(ip, reason=reason, ttl_seconds=block_duration)
        log.warn("brute_force.extended_block", ip=ip, username=clean_username, count=count)
        return count, 60, True

    elif count >= settings.brute_force_block_threshold:
        block_duration = settings.brute_force_block_ttl_seconds
        reason = f"Brute-force warning threshold exceeded ({count} failed login attempts for '{clean_username}')"
        await block_ip(ip, reason=reason, ttl_seconds=block_duration)
        log.warn("brute_force.temporary_block", ip=ip, username=clean_username, count=count)
        return count, 40, True

    elif count >= settings.brute_force_warn_threshold:
        log.info("brute_force.warning", ip=ip, username=clean_username, count=count)
        return count, 20, False

    return count, 0, False


async def record_login_success(ip: str, username: str) -> None:
    """
    Reset brute-force failure counter upon successful authentication.
    """
    ip_key = get_rate_limit_ip_key(ip)
    clean_username = username.strip().lower()
    redis_key = f"bf:{ip_key}:{clean_username}"

    # In-memory
    async with _in_memory_bf_lock:
        _in_memory_bf.pop(redis_key, None)

    # Redis
    try:
        redis = get_redis()
        await redis.delete(redis_key)
    except Exception:
        pass


async def get_failed_attempts(ip: str, username: str) -> int:
    """
    Get current failed login attempts count for (ip, username).
    """
    ip_key = get_rate_limit_ip_key(ip)
    clean_username = username.strip().lower()
    redis_key = f"bf:{ip_key}:{clean_username}"

    try:
        redis = get_redis()
        val = await redis.get(redis_key)
        if val is not None:
            return int(val)
    except Exception:
        pass

    async with _in_memory_bf_lock:
        if redis_key in _in_memory_bf:
            count, exp = _in_memory_bf[redis_key]
            if time.time() <= exp:
                return count
            _in_memory_bf.pop(redis_key, None)

    return 0
