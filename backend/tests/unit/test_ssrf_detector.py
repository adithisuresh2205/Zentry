"""
Phase 11 — Dedicated SSRF (Server-Side Request Forgery) Detector Unit Tests
===========================================================================
Tests all BLOCK and ALLOW cases specified in SentinelGate Master Plan.
"""
from __future__ import annotations

import pytest

from backend.schemas.context import GatewayContext
from backend.threat_detection.normalizer import extract_inspection_targets
from backend.threat_detection.rules.ssrf import SSRFRule


@pytest.fixture
def ssrf_rule() -> SSRFRule:
    return SSRFRule()


def check_ssrf(rule: SSRFRule, url_val: str) -> bool:
    ctx = GatewayContext(
        client_ip="127.0.0.1",
        method="GET",
        path="/api/webhook",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        query_params={"url": url_val},
    )
    targets = extract_inspection_targets(ctx)
    matches = rule.inspect(ctx, targets)
    return len(matches) > 0


class TestSSRFDetector:
    """Master Plan Test Specifications for SSRF Detection."""

    @pytest.mark.parametrize(
        "payload",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:8080/admin",
            "http://localhost:3000/internal",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_flushall",
            "dict://127.0.0.1:11211/stat",
            "http://192.168.1.1/router",
            "http://10.0.0.5/secrets",
            "https://instance-data/latest/meta-data",
        ],
    )
    def test_ssrf_block_cases(self, ssrf_rule: SSRFRule, payload: str) -> None:
        """Every cloud metadata and internal address access must be blocked."""
        assert check_ssrf(ssrf_rule, payload) is True, f"Failed to detect SSRF: {payload}"

    @pytest.mark.parametrize(
        "payload",
        [
            "https://api.github.com/events",
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXX",
            "https://example.com/webhook",
            "https://my-external-service.io/data",
            "http://public-site.org/index.html",
        ],
    )
    def test_ssrf_allow_cases(self, ssrf_rule: SSRFRule, payload: str) -> None:
        """Legitimate external URLs must be allowed."""
        assert check_ssrf(ssrf_rule, payload) is False, f"False positive on: {payload}"
