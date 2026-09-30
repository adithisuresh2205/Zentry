"""
SentinelGate — HTTP Method Abuse Detection Rule
===============================================
Enforces strict HTTP method allowlisting per endpoint and universally blocks
dangerous HTTP methods (TRACE, TRACK, CONNECT) to prevent XST (Cross-Site Tracing)
and proxy tunneling attacks.
Severity: MEDIUM (+15 risk), Blocks directly with HTTP 405.
"""
from __future__ import annotations

from backend.schemas.context import GatewayContext, ThreatMatch
from backend.threat_detection.normalizer import InspectionTarget
from backend.threat_detection.rules.base import DetectionRule

# Methods universally forbidden across the gateway
DANGEROUS_METHODS = {"TRACE", "TRACK", "CONNECT"}

# Known endpoint method policies
ENDPOINT_ALLOWED_METHODS: dict[str, set[str]] = {
    "/auth/login": {"POST", "OPTIONS"},
    "/auth/register": {"POST", "OPTIONS"},
    "/auth/refresh": {"POST", "OPTIONS"},
    "/auth/logout": {"POST", "OPTIONS"},
    "/auth/me": {"GET", "OPTIONS"},
    "/health": {"GET", "HEAD", "OPTIONS"},
}


class MethodAbuseRule(DetectionRule):
    rule_id = "METHOD_ABUSE_001"
    name = "HTTP Method Abuse"
    category = "METHOD_ABUSE"
    severity = "MEDIUM"
    risk_delta = 15
    blocks_directly = True
    status_code = 405

    def inspect(
        self,
        ctx: GatewayContext,
        targets: list[InspectionTarget],
    ) -> list[ThreatMatch]:
        if not self.enabled:
            return []

        method = ctx.method.upper()

        # 1. Universally forbidden HTTP methods (e.g. TRACE for XST attacks)
        if method in DANGEROUS_METHODS:
            return [
                ThreatMatch(
                    rule_id="METHOD_DANGEROUS",
                    category="METHOD_ABUSE",
                    severity="HIGH",
                    risk_delta=20,
                    details=f"Forbidden HTTP method '{method}' rejected",
                    target="method",
                )
            ]

        # 2. Path-specific method restrictions
        normalized_path = ctx.path.rstrip("/")
        allowed_methods = ENDPOINT_ALLOWED_METHODS.get(normalized_path)
        if allowed_methods and method not in allowed_methods:
            return [
                ThreatMatch(
                    rule_id="METHOD_NOT_ALLOWED",
                    category="METHOD_ABUSE",
                    severity="MEDIUM",
                    risk_delta=15,
                    details=f"HTTP method '{method}' not allowed for '{normalized_path}'. Allowed: {sorted(allowed_methods)}",
                    target="method",
                )
            ]

        return []
