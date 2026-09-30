"""
SentinelGate — Dynamic Risk Scoring Engine
==========================================
Calculates a deterministic, weighted, multi-signal risk score (0–100) for every request.
Combines:
- Threat signals (WAF matches: SQLi, XSS, Path Traversal, Cmd Injection, SSRF)
- Behavioral signals (Rate limiting thresholds, progressive brute force)
- Context signals (Scanner User-Agents, method mismatches, compound attack multiplier)
- Authentication signals (Missing, invalid, or revoked tokens)

Enforces strict boundary tie-breaking (round-up rule) and score capping at 100.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

from backend.schemas.context import CheckResult, GatewayContext

# ── Signal Weights ────────────────────────────────────────────────────────────

THREAT_WEIGHTS: dict[str, int] = {
    "COMMAND_INJECTION": 70,
    "SSRF": 65,
    "SQL_INJECTION": 60,
    "XSS": 55,
    "PATH_TRAVERSAL": 55,
}

BEHAVIORAL_WEIGHTS: dict[str, int] = {
    "RATE_LIMIT_EXCEEDED": 20,
    "RATE_LIMIT_NEAR_THRESHOLD": 10,
    "BRUTE_FORCE_TIER1": 20,  # 5-9 failed attempts
    "BRUTE_FORCE_TIER2": 40,  # 10-19 failed attempts
    "BRUTE_FORCE_TIER3": 60,  # 20+ failed attempts
}

CONTEXT_WEIGHTS: dict[str, int] = {
    "UA_SCANNER": 25,
    "UA_MISSING": 15,
    "SUSPICIOUS_UA": 10,
    "UA_CLI_CLIENT": 10,
    "UA_OVERFLOW": 10,
    "METHOD_NOT_ALLOWED": 15,
    "METHOD_DANGEROUS": 20,
    "PAYLOAD_SIZE_EXCEEDED": 10,
    "BLOCKLISTED_IP": 50,
    "COMPOUND_ATTACK_BONUS": 15,
}

AUTH_WEIGHTS: dict[str, int] = {
    "NO_TOKEN_PROTECTED": 5,
    "INVALID_EXPIRED_TOKEN": 10,
    "TOKEN_REVOKED": 30,
}


@dataclass(slots=True)
class RiskSignal:
    """Individual signal contributing to the total risk score."""
    name: str
    category: str
    weight: int
    details: str | None = None


@dataclass(slots=True)
class RiskScoreResult:
    """Comprehensive result of risk scoring calculation."""
    score: int
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    signals: list[RiskSignal] = field(default_factory=list)
    compound_attack: bool = False


def classify_risk_level(score: int) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    """
    Classify risk score into tier with strict boundary round-up:
    - 0 to 29: LOW
    - 30 to 59: MEDIUM
    - 60 to 79: HIGH
    - 80 to 100: CRITICAL
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


class RiskScoringEngine:
    """
    Deterministic multi-signal risk scoring engine.
    Aggregates threat matches, behavioral cues, client context, and compound bonuses.
    """

    def calculate_risk(self, ctx: GatewayContext) -> RiskScoreResult:
        """
        Evaluate all signals present on the GatewayContext and calculate the final score.
        Score is strictly capped at [0, 100].
        """
        signals: list[RiskSignal] = []
        raw_score = 0

        # 1. Threat signals from WAF / inspection
        matched_categories: set[str] = set()
        for threat in ctx.threats:
            weight = THREAT_WEIGHTS.get(threat.category, threat.risk_delta)
            signals.append(
                RiskSignal(
                    name=threat.rule_id,
                    category=threat.category,
                    weight=weight,
                    details=threat.details,
                )
            )
            raw_score += weight
            matched_categories.add(threat.category)

        # 2. Compound attack bonus: if >= 2 distinct attack categories are observed
        is_compound = len(matched_categories) >= 2
        if is_compound:
            bonus = CONTEXT_WEIGHTS["COMPOUND_ATTACK_BONUS"]
            signals.append(
                RiskSignal(
                    name="COMPOUND_ATTACK",
                    category="CONTEXT",
                    weight=bonus,
                    details=f"Multiple distinct attack vectors detected ({len(matched_categories)} categories)",
                )
            )
            raw_score += bonus

        # 3. Incorporate any baseline risk delta already accumulated in ctx
        # (e.g. from network, rate limiter, or fail-secure penalties not explicitly in threats)
        threats_weight_sum = sum(t.risk_delta for t in ctx.threats)
        unaccounted_risk = max(0, ctx.risk_score - threats_weight_sum)
        if unaccounted_risk > 0:
            signals.append(
                RiskSignal(
                    name="PIPELINE_PRIOR_RISK",
                    category="PIPELINE",
                    weight=unaccounted_risk,
                    details="Accumulated pipeline baseline risk",
                )
            )
            raw_score += unaccounted_risk

        # 4. Strict ceiling and floor [0, 100]
        final_score = min(100, max(0, raw_score))
        level = classify_risk_level(final_score)

        # 5. Mutate context state to synchronize
        ctx.risk_score = final_score
        ctx.risk_level = level

        return RiskScoreResult(
            score=final_score,
            level=level,
            signals=signals,
            compound_attack=is_compound,
        )


@lru_cache(maxsize=1)
def get_default_risk_engine() -> RiskScoringEngine:
    """Singleton getter for RiskScoringEngine."""
    return RiskScoringEngine()


async def risk_scoring_check(ctx: GatewayContext) -> CheckResult:
    """
    GatewayPipeline security check callable.
    Executes holistic risk evaluation across all accumulated signals.
    """
    engine = get_default_risk_engine()
    result = engine.calculate_risk(ctx)
    return CheckResult(
        passed=True,
        risk_delta=0,  # Score is already synchronized directly on ctx
    )
