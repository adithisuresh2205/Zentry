"""
Phase 11 — Dedicated XSS (Cross-Site Scripting) Detector Unit Tests
===================================================================
Tests all BLOCK and ALLOW cases specified in SentinelGate Master Plan.
"""
from __future__ import annotations

import pytest

from backend.schemas.context import GatewayContext
from backend.threat_detection.normalizer import extract_inspection_targets
from backend.threat_detection.rules.xss import XSSRule


@pytest.fixture
def xss_rule() -> XSSRule:
    return XSSRule()


def check_xss(rule: XSSRule, value: str) -> bool:
    ctx = GatewayContext(
        client_ip="127.0.0.1",
        method="GET",
        path="/api/search",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        query_params={"q": value},
    )
    targets = extract_inspection_targets(ctx)
    matches = rule.inspect(ctx, targets)
    return len(matches) > 0


class TestXSSDetector:
    """Master Plan Test Specifications for XSS Detection."""

    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            '"><script>alert(document.cookie)</script>',
            "%3cscript%3ealert(1)%3c/script%3e",           # URL-encoded
            "&lt;script&gt;alert(1)&lt;/script&gt;",        # HTML-entity encoded
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "eval('alert(1)')",
        ],
    )
    def test_xss_block_cases(self, xss_rule: XSSRule, payload: str) -> None:
        """Every XSS attack payload must be blocked."""
        assert check_xss(xss_rule, payload) is True, f"Failed to detect XSS in: {payload}"

    @pytest.mark.parametrize(
        "payload",
        [
            "I love <3 pizza",
            "Price: $4.99",
            "Use && to combine commands in terminal",
            "Normal plain comment with no scripts or triggers.",
            "Compare values: 5 < 10 and 10 > 5",
            "user@domain.com, <name@example.org>",
        ],
    )
    def test_xss_allow_cases(self, xss_rule: XSSRule, payload: str) -> None:
        """Legitimate text with math symbols, emoticons, and prices must not trigger false positives."""
        assert check_xss(xss_rule, payload) is False, f"False positive triggered on: {payload}"
