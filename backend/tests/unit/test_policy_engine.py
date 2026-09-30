"""
SentinelGate — Phase 6 Policy Engine Unit Tests
===============================================
Lean, targeted tests covering:
- Decision table tiers: ALLOW (0-29), ALLOW_AND_LOG (30-59), BLOCK (60-79), BLOCK_AND_ALERT (80-100)
- Blocked response body generation with ISO timestamp
- Allowlist relief (IP and path bypasses)
- Pipeline check integration
"""
from __future__ import annotations

import pytest

from backend.config import get_settings
from backend.policy.engine import (
    PolicyAction,
    PolicyEngine,
    get_default_policy_engine,
    policy_enforcement_check,
)
from backend.schemas.context import GatewayContext, ThreatMatch


class TestPolicyEngineUnit:
    """Targeted unit tests for PolicyEngine."""

    @pytest.fixture
    def engine(self) -> PolicyEngine:
        return get_default_policy_engine()

    def test_policy_allow_low_risk(self, engine: PolicyEngine) -> None:
        """Score 0-29 results in ALLOW policy action with debug logging."""
        ctx = GatewayContext(client_ip="192.168.1.1", method="GET", path="/api/items", risk_score=15)
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.ALLOW
        assert decision.status_code == 200
        assert "log_debug" in decision.side_effects
        assert ctx.decision == "ALLOW"

    def test_policy_allow_and_log_medium_risk(self, engine: PolicyEngine) -> None:
        """Score 30-59 results in ALLOW_AND_LOG policy action with audit logging."""
        ctx = GatewayContext(client_ip="192.168.1.1", method="GET", path="/api/items", risk_score=45)
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.ALLOW_AND_LOG
        assert decision.status_code == 200
        assert "audit_log_info" in decision.side_effects
        assert ctx.decision == "LOG"

    def test_policy_block_high_risk(self, engine: PolicyEngine) -> None:
        """Score 60-79 results in BLOCK policy action with HTTP 403."""
        ctx = GatewayContext(
            client_ip="192.168.1.1",
            method="POST",
            path="/api/login",
            risk_score=65,
            threats=[ThreatMatch(rule_id="SQLI_001", category="SQL_INJECTION", severity="HIGH", risk_delta=60)],
        )
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.BLOCK
        assert decision.status_code == 403
        assert "audit_log_warning" in decision.side_effects
        assert decision.response_body is not None
        assert decision.response_body["status"] == "blocked"
        assert decision.response_body["risk_level"] == "HIGH"
        assert "timestamp" in decision.response_body

    def test_policy_block_and_alert_critical_risk(self, engine: PolicyEngine) -> None:
        """Score 80-100 results in BLOCK_AND_ALERT with WebSocket push."""
        ctx = GatewayContext(
            client_ip="192.168.1.1",
            method="POST",
            path="/api/exec",
            risk_score=90,
            risk_level="CRITICAL",
            threats=[ThreatMatch(rule_id="CMD_001", category="COMMAND_INJECTION", severity="CRITICAL", risk_delta=70)],
        )
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.BLOCK_AND_ALERT
        assert decision.status_code == 403
        assert "audit_log_critical" in decision.side_effects
        assert "websocket_push" in decision.side_effects

    def test_policy_allowlist_ip_and_path_relief(
        self, engine: PolicyEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Allowlisted IP or Path bypasses blocking regardless of risk score."""
        settings = get_settings()
        monkeypatch.setattr(settings, "waf_allowlist_ips", ["10.0.0.99"])
        monkeypatch.setattr(settings, "waf_allowlist_paths", ["/api/internal/probe"])

        # Test IP allowlist relief
        ctx_ip = GatewayContext(client_ip="10.0.0.99", method="GET", path="/api/data", risk_score=85)
        decision_ip = engine.evaluate(ctx_ip)
        assert decision_ip.action == PolicyAction.ALLOW
        assert decision_ip.status_code == 200

        # Test Path allowlist relief
        ctx_path = GatewayContext(client_ip="192.168.1.5", method="GET", path="/api/internal/probe", risk_score=95)
        decision_path = engine.evaluate(ctx_path)
        assert decision_path.action == PolicyAction.ALLOW
        assert decision_path.status_code == 200

    @pytest.mark.asyncio
    async def test_policy_enforcement_check_pipeline_callable(self) -> None:
        """Pipeline check blocks on high risk and passes on low risk."""
        # Low risk passes
        ctx_low = GatewayContext(client_ip="1.1.1.1", method="GET", path="/api", risk_score=10)
        res_low = await policy_enforcement_check(ctx_low)
        assert res_low.passed is True

        # High risk blocks with 403
        ctx_high = GatewayContext(client_ip="1.1.1.1", method="GET", path="/api", risk_score=75)
        res_high = await policy_enforcement_check(ctx_high)
        assert res_high.passed is False
        assert res_high.status_code == 403
