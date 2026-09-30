"""
SentinelGate — IP Blocklist Store
=================================
Persistent blocklist for malicious and brute-forcing IPs.
Dual-layer storage:
1. Redis `blocklist:{ip}` with TTL for fast, O(1) checks
2. PostgreSQL / SQLite `ip_blocklist` table for restart persistence (loophole 14)
3. In-memory dictionary fallback with thread-safe eviction
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import delete, select

from backend.cache.redis_client import get_redis
from backend.database.models import IPBlocklist
from backend.database.session import get_session_factory
from backend.network import get_rate_limit_ip_key, normalize_ip
from backend.schemas.context import CheckResult, GatewayContext, ThreatMatch

log = structlog.get_logger(__name__)

# Fallback in-memory store: ip -> (reason, expire_timestamp_epoch | None)
_in_memory_blocks: dict[str, tuple[str, float | None]] = {}


async def block_ip(
    ip: str,
    reason: str = "Automated security block",
    ttl_seconds: int | None = None,
    created_by: str | None = None,
) -> None:
    """
    Block an IP address for `ttl_seconds` (or permanently if None).
    Persists to Redis, in-memory fallback, and database.
    """
    canonical_ip, _ = normalize_ip(ip)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds is not None else None
    expire_epoch = time.time() + ttl_seconds if ttl_seconds is not None else None

    # 1. Update in-memory fallback
    _in_memory_blocks[canonical_ip] = (reason, expire_epoch)

    # 2. Update Redis
    try:
        redis = get_redis()
        redis_key = f"blocklist:{canonical_ip}"
        if ttl_seconds is not None:
            await redis.set(redis_key, reason, ex=max(ttl_seconds, 1))
        else:
            await redis.set(redis_key, reason)
    except Exception as e:
        log.debug("rate_limiter.blocklist.redis_unavailable", ip=canonical_ip, error=str(e))

    # 3. Persist to Database (closes persistence gap across restarts)
    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            # Check if record already exists
            stmt = select(IPBlocklist).where(IPBlocklist.ip == canonical_ip)
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            if existing:
                existing.reason = reason
                existing.blocked_at = now
                existing.expires_at = expires_at
                existing.created_by = created_by
            else:
                new_block = IPBlocklist(
                    ip=canonical_ip,
                    reason=reason,
                    blocked_at=now,
                    expires_at=expires_at,
                    created_by=created_by,
                )
                session.add(new_block)
            await session.commit()
    except Exception as e:
        log.debug("rate_limiter.blocklist.db_save_error", ip=canonical_ip, error=str(e))


async def is_ip_blocked(ip: str) -> tuple[bool, str | None]:
    """
    Check if an IP address is currently blocked.
    Returns (True, reason) if blocked, otherwise (False, None).
    """
    canonical_ip, _ = normalize_ip(ip)
    now_epoch = time.time()

    # 1. Check in-memory fallback
    if canonical_ip in _in_memory_blocks:
        reason, exp = _in_memory_blocks[canonical_ip]
        if exp is None or exp > now_epoch:
            return True, reason
        else:
            del _in_memory_blocks[canonical_ip]

    # 2. Check Redis (O(1) fast path)
    try:
        redis = get_redis()
        val = await redis.get(f"blocklist:{canonical_ip}")
        if val is not None:
            reason_str = val if isinstance(val, str) else val.decode("utf-8")
            return True, reason_str
    except Exception:
        pass

    # 3. Check Database (recovery from restart or Redis cache miss)
    try:
        session_factory = get_session_factory()
        now_dt = datetime.now(timezone.utc)
        async with session_factory() as session:
            stmt = select(IPBlocklist).where(
                IPBlocklist.ip == canonical_ip,
                (IPBlocklist.expires_at.is_(None)) | (IPBlocklist.expires_at > now_dt),
            )
            res = await session.execute(stmt)
            record = res.scalar_one_or_none()

            if record:
                reason = record.reason or "Blocked by security policy"
                # Re-populate Redis cache with remaining TTL
                if record.expires_at:
                    rem_ttl = int((record.expires_at - now_dt).total_seconds())
                    if rem_ttl > 0:
                        try:
                            redis = get_redis()
                            await redis.set(f"blocklist:{canonical_ip}", reason, ex=rem_ttl)
                        except Exception:
                            pass
                        _in_memory_blocks[canonical_ip] = (reason, now_epoch + rem_ttl)
                else:
                    _in_memory_blocks[canonical_ip] = (reason, None)
                return True, reason
    except Exception:
        pass

    return False, None


async def unblock_ip(ip: str) -> bool:
    """
    Remove an IP address from the blocklist across all layers.
    Returns True if unblocked.
    """
    canonical_ip, _ = normalize_ip(ip)
    unblocked = False

    # 1. In-memory
    if canonical_ip in _in_memory_blocks:
        _in_memory_blocks.pop(canonical_ip, None)
        unblocked = True

    # 2. Redis
    try:
        redis = get_redis()
        res = await redis.delete(f"blocklist:{canonical_ip}")
        if res:
            unblocked = True
    except Exception:
        pass

    # 3. Database
    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            stmt = delete(IPBlocklist).where(IPBlocklist.ip == canonical_ip)
            res = await session.execute(stmt)
            await session.commit()
            if res.rowcount and res.rowcount > 0:
                unblocked = True
    except Exception:
        pass

    return unblocked


async def ip_blocklist_check(ctx: GatewayContext) -> CheckResult:
    """
    GatewayPipeline security check:
    Rejects requests originating from blocked IP addresses immediately (HTTP 403).
    """
    blocked, reason = await is_ip_blocked(ctx.client_ip)
    if blocked:
        block_msg = reason or "IP address is blocked due to security policy"
        threat = ThreatMatch(
            rule_id="IP_BLOCKLIST",
            category="BLOCKLIST",
            severity="CRITICAL",
            risk_delta=50,
            details=block_msg,
            target=f"client_ip:{ctx.client_ip}",
        )
        return CheckResult(
            passed=False,
            risk_delta=50,
            threat=threat,
            block_reason=block_msg,
            status_code=403,
        )
    return CheckResult(passed=True)
