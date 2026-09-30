"""
SentinelGate — Risk Engine Package
==================================
Multi-signal risk scoring and threat level classification.
"""
from __future__ import annotations

from backend.risk_engine.scorer import (
    AUTH_WEIGHTS,
    BEHAVIORAL_WEIGHTS,
    CONTEXT_WEIGHTS,
    THREAT_WEIGHTS,
    RiskScoreResult,
    RiskScoringEngine,
    RiskSignal,
    classify_risk_level,
    get_default_risk_engine,
    risk_scoring_check,
)

__all__ = [
    "AUTH_WEIGHTS",
    "BEHAVIORAL_WEIGHTS",
    "CONTEXT_WEIGHTS",
    "THREAT_WEIGHTS",
    "RiskScoreResult",
    "RiskScoringEngine",
    "RiskSignal",
    "classify_risk_level",
    "get_default_risk_engine",
    "risk_scoring_check",
]
