"""
SentinelGate — Rate Limiting & Brute-Force Mitigation Package
=============================================================
Exports sliding-window rate limiter, brute-force detector,
and persistent IP blocklist.
"""
from __future__ import annotations

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
from backend.rate_limiter.limiter import (
    evaluate_rate_limit,
    get_endpoint_tier,
    rate_limiting_check,
)

__all__ = [
    "block_ip",
    "evaluate_rate_limit",
    "get_endpoint_tier",
    "get_failed_attempts",
    "ip_blocklist_check",
    "is_ip_blocked",
    "rate_limiting_check",
    "record_login_failure",
    "record_login_success",
    "unblock_ip",
]
