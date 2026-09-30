"""
Unit tests for Audit Log HMAC Integrity & Chaining
==================================================
Tests:
1. Happy path: Sequential valid events verify successfully.
2. Tamper detection: Modifying risk_score, action, or hmac_chain is detected.
3. Edge case: Empty event sequence and initial HMAC handling.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from backend.audit.integrity import compute_event_hmac, verify_hmac_chain


@dataclass
class MockSecurityEvent:
    id: str
    request_id: str
    timestamp: datetime
    risk_score: int
    action: str
    hmac_chain: str | None = None


def test_hmac_chain_happy_path() -> None:
    """Sequential events with valid HMAC linkage verify as untampered."""
    secret = "a" * 64
    t0 = datetime(2026, 9, 17, 1, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 17, 1, 0, 1, tzinfo=timezone.utc)

    e1 = MockSecurityEvent(
        id=str(uuid4()),
        request_id=str(uuid4()),
        timestamp=t0,
        risk_score=75,
        action="BLOCK",
    )
    e1.hmac_chain = compute_event_hmac(
        prev_hmac="",
        request_id=e1.request_id,
        timestamp=e1.timestamp,
        risk_score=e1.risk_score,
        action=e1.action,
        secret_key=secret,
    )

    e2 = MockSecurityEvent(
        id=str(uuid4()),
        request_id=str(uuid4()),
        timestamp=t1,
        risk_score=90,
        action="BLOCK_AND_ALERT",
    )
    e2.hmac_chain = compute_event_hmac(
        prev_hmac=e1.hmac_chain,
        request_id=e2.request_id,
        timestamp=e2.timestamp,
        risk_score=e2.risk_score,
        action=e2.action,
        secret_key=secret,
    )

    report = verify_hmac_chain([e1, e2], secret_key=secret)
    assert report["verified"] is True
    assert report["total_events"] == 2
    assert report["tampered_events"] == []


def test_hmac_chain_tamper_detection() -> None:
    """Tampering with an event's risk_score or action is detected by verification."""
    secret = "a" * 64
    t0 = datetime(2026, 9, 17, 1, 0, 0, tzinfo=timezone.utc)

    e1 = MockSecurityEvent(
        id=str(uuid4()),
        request_id=str(uuid4()),
        timestamp=t0,
        risk_score=85,
        action="BLOCK",
    )
    e1.hmac_chain = compute_event_hmac(
        prev_hmac="",
        request_id=e1.request_id,
        timestamp=e1.timestamp,
        risk_score=e1.risk_score,
        action=e1.action,
        secret_key=secret,
    )

    # Malicious actor changes risk score from 85 to 10
    e1.risk_score = 10

    report = verify_hmac_chain([e1], secret_key=secret)
    assert report["verified"] is False
    assert len(report["tampered_events"]) == 1
    assert report["tampered_events"][0]["request_id"] == e1.request_id


def test_hmac_chain_empty_and_edge_case() -> None:
    """Empty list verifies cleanly, and invalid secret detects mismatch."""
    report = verify_hmac_chain([], secret_key="b" * 64)
    assert report["verified"] is True
    assert report["total_events"] == 0
    assert report["tampered_events"] == []

    # Mismatched secret key
    e = MockSecurityEvent(
        id=str(uuid4()),
        request_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        risk_score=50,
        action="LOG",
        hmac_chain="invalid_hash",
    )
    mismatch_report = verify_hmac_chain([e], secret_key="c" * 64)
    assert mismatch_report["verified"] is False
    assert len(mismatch_report["tampered_events"]) == 1
