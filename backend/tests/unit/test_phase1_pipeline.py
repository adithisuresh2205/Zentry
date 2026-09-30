"""
Phase 1 — Unit Tests: Gateway Pipeline & Security Check Execution
==================================================================
Direct unit tests for GatewayPipeline, SecurityCheck results,
risk accumulation, threat attachment, fail-secure check error handling,
and apply_security_headers.
"""
from __future__ import annotations

import pytest
from starlette.responses import Response

from backend.gateway import GatewayPipeline, apply_security_headers
from backend.schemas.context import CheckResult, GatewayContext, ThreatMatch


class TestGatewayPipelineExecution:
    """Unit tests for the GatewayPipeline class."""

    @pytest.mark.asyncio
    async def test_empty_pipeline_passes(self) -> None:
        pipeline = GatewayPipeline()
        ctx = GatewayContext(client_ip="127.0.0.1", method="GET", path="/api/test")
        res = await pipeline.execute(ctx)
        assert res.passed is True
        assert ctx.decision == "ALLOW"
        assert ctx.risk_score == 0

    @pytest.mark.asyncio
    async def test_passing_check_with_risk_delta_and_threat(self) -> None:
        pipeline = GatewayPipeline()

        async def soft_check(c: GatewayContext) -> CheckResult:
            threat = ThreatMatch(
                rule_id="UA_SUSPICIOUS",
                category="SUSPICIOUS_CLIENT",
                severity="LOW",
                risk_delta=15,
                details="curl user-agent",
            )
            return CheckResult(passed=True, risk_delta=15, threat=threat)

        pipeline.register_check("soft_check", soft_check)
        ctx = GatewayContext(client_ip="192.168.1.100", method="GET", path="/api/items")
        res = await pipeline.execute(ctx)

        assert res.passed is True
        assert ctx.risk_score == 15
        assert len(ctx.threats) == 1
        assert ctx.threats[0].rule_id == "UA_SUSPICIOUS"
        assert ctx.decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_blocking_check_short_circuits(self) -> None:
        pipeline = GatewayPipeline()
        second_called = False

        async def blocking_check(c: GatewayContext) -> CheckResult:
            threat = ThreatMatch(
                rule_id="IP_BLOCK",
                category="BLOCKLIST",
                severity="CRITICAL",
                risk_delta=80,
            )
            return CheckResult(
                passed=False,
                risk_delta=80,
                threat=threat,
                block_reason="IP explicitly blocked",
                status_code=403,
            )

        async def second_check(c: GatewayContext) -> CheckResult:
            nonlocal second_called
            second_called = True
            return CheckResult(passed=True)

        pipeline.register_check("blocking_check", blocking_check)
        pipeline.register_check("second_check", second_check)

        ctx = GatewayContext(client_ip="10.0.0.99", method="POST", path="/api/data")
        res = await pipeline.execute(ctx)

        assert res.passed is False
        assert second_called is False  # Short-circuit verified
        assert ctx.decision == "BLOCK"
        assert ctx.risk_score == 80
        assert ctx.risk_level == "CRITICAL"
        assert ctx.blocked_reason == "IP explicitly blocked"
        assert ctx.response_status == 403

    @pytest.mark.asyncio
    async def test_fail_secure_on_check_exception(self) -> None:
        pipeline = GatewayPipeline()

        async def faulty_check(c: GatewayContext) -> CheckResult:
            raise RuntimeError("Database connection crashed inside check")

        pipeline.register_check("faulty", faulty_check)
        ctx = GatewayContext(client_ip="127.0.0.1", method="GET", path="/api/data")
        res = await pipeline.execute(ctx)

        assert res.passed is True
        # Fail-secure added risk score of 25
        assert ctx.risk_score == 25


class TestGatewayContextAndHeaders:
    """Unit tests for GatewayContext risk accumulation and apply_security_headers."""

    def test_risk_score_levels_and_capping(self) -> None:
        ctx = GatewayContext(client_ip="127.0.0.1", method="GET", path="/")
        assert ctx.risk_score == 0
        assert ctx.risk_level == "LOW"

        ctx.add_risk(35)
        assert ctx.risk_score == 35
        assert ctx.risk_level == "MEDIUM"

        ctx.add_risk(30)
        assert ctx.risk_score == 65
        assert ctx.risk_level == "HIGH"

        ctx.add_risk(20)
        assert ctx.risk_score == 85
        assert ctx.risk_level == "CRITICAL"

        # Cap test: adding 100 doesn't exceed 100
        ctx.add_risk(100)
        assert ctx.risk_score == 100
        assert ctx.risk_level == "CRITICAL"

    def test_apply_security_headers(self) -> None:
        ctx = GatewayContext(
            request_id="custom-uuid-9999",
            client_ip="1.2.3.4",
            method="GET",
            path="/",
        )
        ctx.add_risk(65)
        response = Response(content="OK", status_code=200)
        apply_security_headers(response, ctx)

        h = response.headers
        assert h["X-Request-ID"] == "custom-uuid-9999"
        assert h["X-Risk-Score"] == "65"
        assert h["X-Risk-Level"] == "HIGH"
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert h["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in h
        assert "Strict-Transport-Security" in h
