"""
SentinelGate — Phase 5 Risk Scoring Engine Unit Tests
=====================================================
Lean, targeted tests covering:
- Base scoring with zero signals (happy path)
- Single threat scoring (SQLi -> score 60, level HIGH)
- Multi-signal compound scoring (threat + compound bonus + scanner UA -> CRITICAL)
- Boundary round-up tie-breaking (30 -> MEDIUM, 60 -> HIGH, 80 -> CRITICAL)
- Hard ceiling at 100 (overflow protection)
- Pipeline check integration
"""
from __future__ import annotations

import pytest

from backend.risk_engine.scorer import (
    RiskScoringEngine,
    classify_risk_level,
    get_default_risk_engine,
    risk_scoring_check,
)
from backend.schemas.context import GatewayContext, ThreatMatch


class TestRiskScorerUnit:
    """Targeted unit tests for the Risk Scoring Engine."""

    @pytest.fixture
    def engine(self) -> RiskScoringEngine:
        return get_default_risk_engine()

    def test_happy_path_zero_signals(self, engine: RiskScoringEngine) -> None:
        """Clean request with no threat matches yields score 0 and LOW risk."""
        ctx = GatewayContext(client_ip="192.168.1.1", method="GET", path="/api/items")
        result = engine.calculate_risk(ctx)
        assert result.score == 0
        assert result.level == "LOW"
        assert result.compound_attack is False
        assert ctx.risk_score == 0
        assert ctx.risk_level == "LOW"

    def test_single_threat_signal_sqli(self, engine: RiskScoringEngine) -> None:
        """Single SQLi threat match assigns score 60 and HIGH risk level."""
        ctx = GatewayContext(client_ip="192.168.1.1", method="GET", path="/api/items")
        ctx.threats.append(
            ThreatMatch(
                rule_id="SQLI_001",
                category="SQL_INJECTION",
                severity="HIGH",
                risk_delta=60,
                target="query:q",
            )
        )
        result = engine.calculate_risk(ctx)
        assert result.score == 60
        assert result.level == "HIGH"
        assert result.compound_attack is False
        assert ctx.risk_score == 60
        assert ctx.risk_level == "HIGH"

    def test_multi_signal_compound_attack_bonus(self, engine: RiskScoringEngine) -> None:
        """Multiple distinct threat categories trigger compound attack bonus (+15)."""
        ctx = GatewayContext(client_ip="192.168.1.1", method="POST", path="/api/login")
        # SQL Injection (+60)
        ctx.threats.append(
            ThreatMatch(
                rule_id="SQLI_001",
                category="SQL_INJECTION",
                severity="HIGH",
                risk_delta=60,
            )
        )
        # XSS (+55)
        ctx.threats.append(
            ThreatMatch(
                rule_id="XSS_001",
                category="XSS",
                severity="HIGH",
                risk_delta=55,
            )
        )
        # Scanner UA from context (+25 prior accumulated)
        ctx.threats.append(
            ThreatMatch(
                rule_id="UA_SCANNER",
                category="SUSPICIOUS_UA",
                severity="HIGH",
                risk_delta=25,
            )
        )

        result = engine.calculate_risk(ctx)
        assert result.compound_attack is True
        # 60 + 55 + 25 + 15 (compound) = 155 -> capped at 100
        assert result.score == 100
        assert result.level == "CRITICAL"

    def test_boundary_round_up_rule(self) -> None:
        """Exact boundary values must round UP to higher severity."""
        assert classify_risk_level(29) == "LOW"
        assert classify_risk_level(30) == "MEDIUM"  # Boundary: round UP
        assert classify_risk_level(59) == "MEDIUM"
        assert classify_risk_level(60) == "HIGH"    # Boundary: round UP
        assert classify_risk_level(79) == "HIGH"
        assert classify_risk_level(80) == "CRITICAL"# Boundary: round UP
        assert classify_risk_level(100) == "CRITICAL"

    def test_score_hard_ceiling_at_100(self, engine: RiskScoringEngine) -> None:
        """Score must never exceed 100 even with extreme cumulative signals."""
        ctx = GatewayContext(client_ip="192.168.1.1", method="POST", path="/api/run")
        ctx.threats.append(
            ThreatMatch(rule_id="CMD_001", category="COMMAND_INJECTION", severity="CRITICAL", risk_delta=70)
        )
        ctx.threats.append(
            ThreatMatch(rule_id="SSRF_001", category="SSRF", severity="HIGH", risk_delta=65)
        )
        ctx.threats.append(
            ThreatMatch(rule_id="SQLI_001", category="SQL_INJECTION", severity="HIGH", risk_delta=60)
        )
        result = engine.calculate_risk(ctx)
        assert result.score == 100
        assert result.level == "CRITICAL"

    @pytest.mark.asyncio
    async def test_risk_scoring_check_pipeline_callable(self) -> None:
        """Pipeline callable synchronizes score and level on GatewayContext."""
        ctx = GatewayContext(client_ip="10.0.0.1", method="GET", path="/api/data")
        ctx.threats.append(
            ThreatMatch(rule_id="UA_SCANNER", category="SUSPICIOUS_UA", severity="HIGH", risk_delta=25)
        )
        check_result = await risk_scoring_check(ctx)
        assert check_result.passed is True
        assert ctx.risk_score == 25
        assert ctx.risk_level == "LOW"
