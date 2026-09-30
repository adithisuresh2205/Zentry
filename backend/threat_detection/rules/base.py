"""
SentinelGate — Threat Detection Rule Base
=========================================
Defines the base DetectionRule abstraction for all WAF inspection rules.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Literal

from backend.schemas.context import GatewayContext, ThreatMatch
from backend.threat_detection.normalizer import InspectionTarget


class DetectionRule(ABC):
    """Base class for all WAF inspection rules."""

    rule_id: str
    name: str
    category: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_delta: int
    enabled: bool = True
    blocks_directly: bool = True
    status_code: int = 403

    @abstractmethod
    def inspect(
        self,
        ctx: GatewayContext,
        targets: list[InspectionTarget],
    ) -> list[ThreatMatch]:
        """Inspect the request context and targets, returning all matched threats."""
        ...


class RegexRule(DetectionRule):
    """Convenience base class for regex-based threat rules."""

    compiled_patterns: list[re.Pattern[str]]
    allowed_locations: set[str] | None = None
    ignored_locations: set[str] | None = None

    def inspect(
        self,
        ctx: GatewayContext,
        targets: list[InspectionTarget],
    ) -> list[ThreatMatch]:
        if not self.enabled:
            return []

        matches: list[ThreatMatch] = []
        for target in targets:
            loc = target.location
            # Filter locations if configured
            if self.allowed_locations and not any(loc.startswith(prefix) for prefix in self.allowed_locations):
                continue
            if self.ignored_locations and any(loc.startswith(prefix) for prefix in self.ignored_locations):
                continue

            for pattern in self.compiled_patterns:
                m = pattern.search(target.normalized_value)
                if m:
                    matched_snippet = m.group(0)[:60]
                    matches.append(
                        ThreatMatch(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity=self.severity,
                            risk_delta=self.risk_delta,
                            details=f"{self.name} detected in {loc}: '{matched_snippet}'",
                            target=loc,
                        )
                    )
                    # Once matched for this target, continue to next target
                    break

        return matches
