"""
SentinelGate — Threat Detection (WAF) Package
==============================================
Provides deep request inspection against OWASP Top 10 vulnerabilities.
"""
from __future__ import annotations

from backend.threat_detection.engine import (
    ThreatDetectionEngine,
    get_default_engine,
    threat_detection_check,
)
from backend.threat_detection.normalizer import (
    InspectionTarget,
    extract_inspection_targets,
    normalize_text,
)

__all__ = [
    "InspectionTarget",
    "ThreatDetectionEngine",
    "extract_inspection_targets",
    "get_default_engine",
    "normalize_text",
    "threat_detection_check",
]
