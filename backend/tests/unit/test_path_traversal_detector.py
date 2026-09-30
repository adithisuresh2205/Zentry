"""
Phase 11 — Dedicated Path Traversal Detector Unit Tests
========================================================
Tests all BLOCK and ALLOW cases specified in SentinelGate Master Plan.
"""
from __future__ import annotations

import pytest

from backend.schemas.context import GatewayContext
from backend.threat_detection.normalizer import extract_inspection_targets
from backend.threat_detection.rules.path_traversal import PathTraversalRule


@pytest.fixture
def traversal_rule() -> PathTraversalRule:
    return PathTraversalRule()


def check_traversal(rule: PathTraversalRule, path_or_query: str) -> bool:
    ctx = GatewayContext(
        client_ip="127.0.0.1",
        method="GET",
        path="/api/files",
        query_params={"file": path_or_query},
    )
    targets = extract_inspection_targets(ctx)
    matches = rule.inspect(ctx, targets)
    return len(matches) > 0


class TestPathTraversalDetector:
    """Master Plan Test Specifications for Path Traversal Detection."""

    @pytest.mark.parametrize(
        "payload",
        [
            "../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",           # URL-encoded
            "..%252F..%252Fetc%252Fpasswd",       # Double URL-encoded
            "/proc/self/environ",
            r"..\..\windows\system32\config\sam",  # Windows SAM file
            "../../../../var/log/auth.log",
            "../.env",
            "../../.git/config",
            "/boot.ini",
        ],
    )
    def test_path_traversal_block_cases(
        self, traversal_rule: PathTraversalRule, payload: str
    ) -> None:
        """Every path traversal and sensitive file access attempt must be blocked."""
        assert check_traversal(traversal_rule, payload) is True, f"Failed to detect traversal: {payload}"

    @pytest.mark.parametrize(
        "payload",
        [
            "/api/users/profile",
            "/api/search?q=product",
            "document_v1.pdf",
            "report_2026.xlsx",
            "public/assets/logo.png",
            "item_dot.name.txt",
        ],
    )
    def test_path_traversal_allow_cases(
        self, traversal_rule: PathTraversalRule, payload: str
    ) -> None:
        """Legitimate file names and API routes must not trigger false positives."""
        assert check_traversal(traversal_rule, payload) is False, f"False positive on: {payload}"
