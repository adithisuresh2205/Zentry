"""
Phase 11 — Dedicated SQL Injection Detector Unit Tests
======================================================
Tests all BLOCK cases and ALLOW cases specified in SentinelGate Master Plan.
"""
from __future__ import annotations

import pytest

from backend.schemas.context import GatewayContext
from backend.threat_detection.normalizer import extract_inspection_targets
from backend.threat_detection.rules.sqli import SQLInjectionRule


@pytest.fixture
def sqli_rule() -> SQLInjectionRule:
    return SQLInjectionRule()


def check_sqli(rule: SQLInjectionRule, query_val: str) -> bool:
    ctx = GatewayContext(
        client_ip="127.0.0.1",
        method="GET",
        path="/api/search",
        query_params={"q": query_val},
    )
    targets = extract_inspection_targets(ctx)
    matches = rule.inspect(ctx, targets)
    return len(matches) > 0


class TestSQLiDetector:
    """Master Plan Test Specifications for SQL Injection."""

    @pytest.mark.parametrize(
        "payload",
        [
            "' OR 1=1 --",
            "' OR 1=1 #",
            "UNION SELECT * FROM users",
            "'; DROP TABLE users; --",
            "SLEEP(5)",
            "1 AND BENCHMARK(1000000,MD5(1))",
            "%27%20OR%201%3D1%20--",          # URL-encoded
            "%2527%2520OR%25201%253D1%2520--",  # Double-encoded
            "' oR 1=1--",                     # Mixed case
            "admin' UNION ALL SELECT NULL, password FROM users--",
            "1; INSERT INTO users VALUES ('hacked');",
        ],
    )
    def test_sqli_block_cases(self, sqli_rule: SQLInjectionRule, payload: str) -> None:
        """Every attack payload must be detected and matched."""
        assert check_sqli(sqli_rule, payload) is True, f"Failed to detect SQLi in: {payload}"

    @pytest.mark.parametrize(
        "payload",
        [
            "hello world",
            "search for products",
            "user@email.com",
            "john o'brien",
            "select few items",
            "order by price ascending",
            "drop shipment tracking",
        ],
    )
    def test_sqli_allow_cases(self, sqli_rule: SQLInjectionRule, payload: str) -> None:
        """Legitimate search queries and apostrophes must not trigger false positives."""
        assert check_sqli(sqli_rule, payload) is False, f"False positive triggered on: {payload}"
