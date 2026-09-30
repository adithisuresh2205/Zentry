"""
Phase 11 — Dedicated False-Positive Verification Test Suite
==========================================================
Verifies that legitimate business inputs, complex names, markdown,
base64 blobs, and SQL-like vocabulary do NOT trigger false positives
across the entire inspection pipeline.
"""
from __future__ import annotations

import base64
import json

import pytest

from backend.schemas.context import GatewayContext
from backend.threat_detection.engine import ThreatDetectionEngine


@pytest.fixture
def engine() -> ThreatDetectionEngine:
    return ThreatDetectionEngine()


class TestFalsePositives:
    """Master Plan Test Specifications for False-Positive Prevention."""

    def test_sql_like_vocabulary_in_product_descriptions(
        self, engine: ThreatDetectionEngine
    ) -> None:
        """Legitimate business strings with 'select', 'from', 'drop', 'table' must pass."""
        test_phrases = [
            "Please select few items for order fulfillment.",
            "Drop shipment tracking is available for warehouse orders.",
            "Insert key into slot A and table discussion points.",
            "Update: the project timeline has been altered.",
            "Order by priority before shipping.",
        ]
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        hdr = {"user-agent": ua}
        for phrase in test_phrases:
            ctx = GatewayContext(
                client_ip="10.0.0.1",
                method="POST",
                path="/api/products",
                user_agent=ua,
                headers=hdr,
                query_params={"description": phrase},
                body=json.dumps({"description": phrase}).encode("utf-8"),
            )
            matches = engine.inspect(ctx)
            assert len(matches) == 0, f"False positive on benign phrase: {phrase}"

    def test_names_with_apostrophes_and_hyphens(
        self, engine: ThreatDetectionEngine
    ) -> None:
        """Names such as O'Brien, D'Angelo, or hyphenated names must pass."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        hdr = {"user-agent": ua}
        names = ["Conan O'Brien", "D'Angelo Russell", "Mary-Jane Watson", "O'Connor & Sons"]
        for name in names:
            ctx = GatewayContext(
                client_ip="10.0.0.1",
                method="POST",
                path="/api/users/profile",
                user_agent=ua,
                headers=hdr,
                query_params={"full_name": name},
                body=json.dumps({"full_name": name}).encode("utf-8"),
            )
            matches = engine.inspect(ctx)
            assert len(matches) == 0, f"False positive on benign name: {name}"

    def test_markdown_and_math_comparisons(
        self, engine: ThreatDetectionEngine
    ) -> None:
        """Documentation containing <, >, &, or markdown must pass."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        hdr = {"user-agent": ua}
        docs = [
            "We check if x < 10 and y > 20 before executing.",
            "Use git add && git commit to stage files.",
            "Formula: a < b <= c.",
            "Review items: item #1 and item #2.",
        ]
        for doc in docs:
            ctx = GatewayContext(
                client_ip="10.0.0.1",
                method="POST",
                path="/api/docs",
                user_agent=ua,
                headers=hdr,
                query_params={"content": doc},
                body=json.dumps({"content": doc}).encode("utf-8"),
            )
            matches = engine.inspect(ctx)
            assert len(matches) == 0, f"False positive on documentation text: {doc}"

    def test_base64_encoded_payloads(
        self, engine: ThreatDetectionEngine
    ) -> None:
        """Legitimate base64 image / binary chunks must not trigger rules."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        hdr = {"user-agent": ua}
        raw_binary = b"AlegitimatePNGfilecontentwithsomemetadata1234567890" * 10
        b64_str = base64.b64encode(raw_binary).decode("utf-8")
        ctx = GatewayContext(
            client_ip="10.0.0.1",
            method="POST",
            path="/api/upload",
            user_agent=ua,
            headers=hdr,
            body=json.dumps({"avatar_b64": b64_str}).encode("utf-8"),
        )
        matches = engine.inspect(ctx)
        assert len(matches) == 0, "False positive on legitimate base64 content"

    def test_large_legitimate_json_payload(
        self, engine: ThreatDetectionEngine
    ) -> None:
        """Large structured JSON under the payload size limit must pass cleanly."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        hdr = {"user-agent": ua}
        items = [{"id": i, "name": f"Item #{i}", "tags": ["electronics", "sale"]} for i in range(100)]
        ctx = GatewayContext(
            client_ip="10.0.0.1",
            method="POST",
            path="/api/bulk-import",
            user_agent=ua,
            headers=hdr,
            body=json.dumps({"items": items}).encode("utf-8"),
        )
        matches = engine.inspect(ctx)
        assert len(matches) == 0, "False positive on large legitimate JSON batch"
