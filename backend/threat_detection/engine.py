"""
SentinelGate — Threat Detection Engine (WAF)
============================================
OWASP Top 10 2021-aligned Deep Request Inspection Engine.
Inspects paths, query parameters, headers, and request bodies using deterministic regex rules
and normalized evasion-resistant representations.
"""
from __future__ import annotations

from functools import lru_cache

import structlog

from backend.config import get_settings
from backend.schemas.context import CheckResult, GatewayContext, ThreatMatch
from backend.threat_detection.normalizer import extract_inspection_targets
from backend.threat_detection.rules import DetectionRule, get_default_rules

log = structlog.get_logger(__name__)


class ThreatDetectionEngine:
    """
    Core WAF Engine orchestrating all detection rules.
    Performs evasion normalization and comprehensive target inspection.
    """

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules: list[DetectionRule] = rules if rules is not None else get_default_rules()

    def inspect(self, ctx: GatewayContext) -> list[ThreatMatch]:
        """
        Run all enabled rules against normalized request targets.
        Bypasses inspection if WAF is disabled or target is allowlisted.
        """
        settings = get_settings()
        if not settings.waf_enabled:
            return []

        # False-positive allowlist check (IP and Path)
        if ctx.client_ip in settings.waf_allowlist_ips:
            log.debug("waf.allowlist.ip_bypassed", ip=ctx.client_ip)
            return []

        for allow_path in settings.waf_allowlist_paths:
            if ctx.path.startswith(allow_path):
                log.debug("waf.allowlist.path_bypassed", path=ctx.path)
                return []

        # Extract and normalize all request components
        targets = extract_inspection_targets(ctx)

        all_matches: list[ThreatMatch] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            matches = rule.inspect(ctx, targets)
            if matches:
                all_matches.extend(matches)

        return all_matches

    def evaluate(self, ctx: GatewayContext) -> CheckResult:
        """
        Evaluate request and return pipeline CheckResult:
        - If any rule matches with blocks_directly=True: blocks request (HTTP 403 or 405)
        - If only non-blocking signals match (e.g. suspicious UA): allows request but adds risk
        - If no matches: passes with zero risk
        """
        matches = self.inspect(ctx)
        if not matches:
            return CheckResult(passed=True, risk_delta=0)

        # Aggregate total risk delta capped at 100
        total_risk_delta = min(100, sum(m.risk_delta for m in matches))

        # Check for directly blocking threat rules
        blocking_match: ThreatMatch | None = None
        blocking_status_code = 403

        # Map matched threat rule_id and category to rule object
        rule_map = {r.rule_id: r for r in self.rules}
        category_map = {r.category: r for r in self.rules}

        for match in matches:
            rule = rule_map.get(match.rule_id) or category_map.get(match.category)
            if rule and rule.blocks_directly:
                blocking_match = match
                blocking_status_code = rule.status_code
                break

        # Append non-primary threat matches to context so all detections are preserved
        if len(matches) > 1:
            for extra in matches[1:]:
                ctx.threats.append(extra)

        primary_threat = matches[0]

        settings = get_settings()
        if blocking_match and settings.waf_block_threats:
            log.warn(
                "waf.threat.blocked",
                rule_id=blocking_match.rule_id,
                category=blocking_match.category,
                path=ctx.path,
                ip=ctx.client_ip,
                target=blocking_match.target,
            )
            return CheckResult(
                passed=False,
                risk_delta=total_risk_delta,
                threat=primary_threat,
                block_reason=blocking_match.details or f"WAF Block: {blocking_match.category}",
                status_code=blocking_status_code,
            )

        # Non-blocking signal (e.g. User-Agent warning) or detection-only mode
        log.info(
            "waf.threat.flagged",
            category=primary_threat.category,
            risk_delta=total_risk_delta,
            path=ctx.path,
        )
        return CheckResult(
            passed=True,
            risk_delta=total_risk_delta,
            threat=primary_threat,
        )


@lru_cache(maxsize=1)
def get_default_engine() -> ThreatDetectionEngine:
    """Return the cached default ThreatDetectionEngine instance."""
    return ThreatDetectionEngine()


async def threat_detection_check(ctx: GatewayContext) -> CheckResult:
    """
    GatewayPipeline security check callable.
    Dispatches request to the ThreatDetectionEngine.
    """
    engine = get_default_engine()
    return engine.evaluate(ctx)
