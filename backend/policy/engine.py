"""
SentinelGate — Policy Engine
============================
Converts dynamic risk scores into deterministic, enforceable actions.
Enforces the Policy Decision Table:
- 0–29: ALLOW (Forward request, debug log)
- 30–59: ALLOW + LOG (Forward request, audit log entry INFO)
- 60–79: BLOCK (403 Forbidden, audit log entry WARNING)
- 80–100: BLOCK + ALERT (403 Forbidden, audit log CRITICAL, WebSocket push)

Supports administrative allowlist bypasses for false-positive relief.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any

import structlog

from backend.config import get_settings
from backend.schemas.context import CheckResult, GatewayContext

log = structlog.get_logger(__name__)


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_AND_LOG = "ALLOW_AND_LOG"
    BLOCK = "BLOCK"
    BLOCK_AND_ALERT = "BLOCK_AND_ALERT"


@dataclass(slots=True)
class PolicyDecision:
    """Deterministic security action determined by the Policy Engine."""
    action: PolicyAction
    status_code: int = 200
    block_reason: str | None = None
    side_effects: list[str] = field(default_factory=list)
    response_body: dict[str, Any] | None = None


class PolicyEngine:
    """
    Evaluates request context and determines the authoritative policy decision.
    """

    def evaluate(self, ctx: GatewayContext) -> PolicyDecision:
        """
        Evaluate context against risk thresholds and allowlists.
        """
        settings = get_settings()
        ctx._update_risk_level()

        # 1. Allowlist Relief (IP and Path)
        # Allowlisted IPs or paths bypass threat blocking (not rate limiting)
        if ctx.client_ip in settings.waf_allowlist_ips:
            log.info("policy.allowlist.ip_bypass", ip=ctx.client_ip, request_id=ctx.request_id)
            ctx.decision = "ALLOW"
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                status_code=200,
                side_effects=["log_debug", "allowlist_ip_bypass"],
            )

        for allow_path in settings.waf_allowlist_paths:
            if ctx.path.startswith(allow_path):
                log.info("policy.allowlist.path_bypass", path=ctx.path, request_id=ctx.request_id)
                ctx.decision = "ALLOW"
                return PolicyDecision(
                    action=PolicyAction.ALLOW,
                    status_code=200,
                    side_effects=["log_debug", "allowlist_path_bypass"],
                )

        score = ctx.risk_score

        # 2. Risk Range Decision Table
        if score >= settings.risk_threshold_critical:  # 80–100
            action = PolicyAction.BLOCK_AND_ALERT
            status_code = 403
            side_effects = ["audit_log_critical", "websocket_push"]
            ctx.decision = "BLOCK"
            ctx.response_status = 403
            if not ctx.blocked_reason:
                ctx.blocked_reason = "Request blocked by SentinelGate security policy (CRITICAL risk)"

        elif score >= settings.risk_threshold_high:  # 60–79
            action = PolicyAction.BLOCK
            status_code = 403
            side_effects = ["audit_log_warning"]
            ctx.decision = "BLOCK"
            ctx.response_status = 403
            if not ctx.blocked_reason:
                ctx.blocked_reason = "Request blocked by SentinelGate security policy (HIGH risk)"

        elif score >= settings.risk_threshold_medium:  # 30–59
            action = PolicyAction.ALLOW_AND_LOG
            status_code = 200
            side_effects = ["audit_log_info"]
            ctx.decision = "LOG"

        else:  # 0–29
            action = PolicyAction.ALLOW
            status_code = 200
            side_effects = ["log_debug"]
            ctx.decision = "ALLOW"

        # 3. Build standardized blocked response body if blocked
        response_body: dict[str, Any] | None = None
        if action in (PolicyAction.BLOCK, PolicyAction.BLOCK_AND_ALERT):
            response_body = {
                "status": "blocked",
                "request_id": ctx.request_id,
                "risk_score": ctx.risk_score,
                "risk_level": ctx.risk_level,
                "threats": [t.category for t in ctx.threats],
                "message": ctx.blocked_reason or "Request blocked by SentinelGate security policy.",
                "timestamp": ctx.timestamp.isoformat(),
            }

        return PolicyDecision(
            action=action,
            status_code=status_code,
            block_reason=ctx.blocked_reason,
            side_effects=side_effects,
            response_body=response_body,
        )


@lru_cache(maxsize=1)
def get_default_policy_engine() -> PolicyEngine:
    """Singleton getter for PolicyEngine."""
    return PolicyEngine()


async def policy_enforcement_check(ctx: GatewayContext) -> CheckResult:
    """
    GatewayPipeline security check callable.
    Enforces the policy decision determined by the PolicyEngine.
    """
    engine = get_default_policy_engine()
    decision = engine.evaluate(ctx)

    if decision.action in (PolicyAction.BLOCK, PolicyAction.BLOCK_AND_ALERT):
        return CheckResult(
            passed=False,
            risk_delta=0,
            block_reason=decision.block_reason,
            status_code=decision.status_code,
        )

    return CheckResult(passed=True, risk_delta=0)
