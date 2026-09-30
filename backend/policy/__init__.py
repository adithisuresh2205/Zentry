"""
SentinelGate — Policy Package
=============================
Enforces security decisions and hardened HTTP response headers.
"""
from __future__ import annotations

from backend.policy.engine import (
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
    get_default_policy_engine,
    policy_enforcement_check,
)
from backend.policy.headers import DEFAULT_SECURITY_HEADERS, apply_security_headers

__all__ = [
    "DEFAULT_SECURITY_HEADERS",
    "PolicyAction",
    "PolicyDecision",
    "PolicyEngine",
    "apply_security_headers",
    "get_default_policy_engine",
    "policy_enforcement_check",
]
