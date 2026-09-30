"""
Unit tests for AuditLogger and Background Worker
================================================
Tests:
1. Happy path: Enqueueing event writes to database with HMAC chain.
2. Fallback: Database write failure falls back to local JSON log.
3. Edge case: Low-risk ALLOW events are skipped from queue.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.audit.logger import AuditLogger
from backend.database.models import SecurityEvent
from backend.schemas.context import GatewayContext, ThreatMatch


@pytest.mark.asyncio
async def test_audit_logger_happy_path(test_db: AsyncSession, tmp_path: Path) -> None:
    """AuditLogger enqueues and saves event to database with computed HMAC."""
    fallback_file = tmp_path / "test_fallback.jsonl"
    logger = AuditLogger(fallback_path=str(fallback_file))
    logger.start()

    ctx = GatewayContext(
        client_ip="192.168.1.50",
        method="POST",
        path="/api/login",
        risk_score=75,
        risk_level="HIGH",
        decision="BLOCK",
        threats=[
            ThreatMatch(
                rule_id="SQLI_001",
                category="SQL_INJECTION",
                severity="HIGH",
                risk_delta=60,
                details="UNION SELECT detected",
            )
        ],
    )

    logger.log_event(ctx, response_code=403, duration_ms=15)
    await logger.flush()
    await logger.stop()

    # Verify event stored in test_db
    stmt = select(SecurityEvent).where(SecurityEvent.request_id == ctx.request_id)
    result = await test_db.execute(stmt)
    event = result.scalar_one_or_none()

    assert event is not None
    assert event.source_ip == "192.168.1.50"
    assert event.risk_score == 75
    assert event.action == "BLOCK"
    assert event.response_code == 403
    assert event.hmac_chain is not None
    assert len(event.hmac_chain) == 64  # SHA256 hex length


@pytest.mark.asyncio
async def test_audit_logger_db_failure_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When DB is unavailable, audit logger writes structured JSON to fallback file."""
    fallback_file = tmp_path / "test_fallback.jsonl"
    logger = AuditLogger(fallback_path=str(fallback_file))

    # Force DB session factory to fail
    def failing_session_factory() -> None:
        raise RuntimeError("Database connection unreachable")

    monkeypatch.setattr("backend.audit.logger.get_session_factory", failing_session_factory)

    logger.start()

    ctx = GatewayContext(
        client_ip="10.0.0.99",
        method="GET",
        path="/api/search",
        risk_score=90,
        risk_level="CRITICAL",
        decision="BLOCK",
    )

    logger.log_event(ctx, response_code=403, duration_ms=8)
    await logger.flush()
    await logger.stop()

    assert fallback_file.exists()
    content = fallback_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    assert data["request_id"] == ctx.request_id
    assert data["source_ip"] == "10.0.0.99"
    assert data["risk_score"] == 90
    assert data["action"] == "BLOCK"


def test_audit_logger_skips_low_risk_allow() -> None:
    """Low-risk clean ALLOW requests are not queued for persistent audit logging."""
    logger = AuditLogger()

    clean_ctx = GatewayContext(
        client_ip="192.168.1.10",
        method="GET",
        path="/api/products",
        risk_score=0,
        risk_level="LOW",
        decision="ALLOW",
    )

    logger.log_event(clean_ctx, response_code=200, duration_ms=5)
    assert logger.queue.qsize() == 0


@pytest.mark.asyncio
async def test_get_security_stats_direct_unit(test_db: AsyncSession) -> None:
    """Direct unit test for get_security_stats computation and list_security_events query."""
    from backend.database.models import User
    from backend.routes.security import get_security_stats, list_security_events

    # 1. Test empty stats
    res_empty = await get_security_stats(test_db)
    assert res_empty.total_requests == 0
    assert res_empty.global_threat_level == "LOW"
    assert len(res_empty.traffic_timeline) >= 6

    # 2. Insert sample event
    ev1 = SecurityEvent(
        id=str(uuid4()),
        request_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip="127.0.0.1",
        client_ipv6=False,
        method="GET",
        path="/api/search",
        threats=[{"category": "SQL_INJECTION", "rule_id": "SQLI_001"}],
        risk_score=95,
        risk_level="CRITICAL",
        action="BLOCK",
        response_code=403,
        duration_ms=10,
        hmac_chain="dummy",
    )
    ev2 = SecurityEvent(
        id=str(uuid4()),
        request_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip="127.0.0.1",
        client_ipv6=False,
        method="GET",
        path="/api/products",
        threats=[],
        risk_score=10,
        risk_level="LOW",
        action="ALLOW",
        response_code=200,
        duration_ms=5,
        hmac_chain="dummy2",
    )
    test_db.add(ev1)
    test_db.add(ev2)
    await test_db.commit()

    # 3. Test populated stats
    res_pop = await get_security_stats(test_db)
    assert res_pop.total_requests == 2
    assert res_pop.blocked_requests == 1
    assert res_pop.allowed_requests == 1
    assert res_pop.global_threat_level == "CRITICAL"
    assert len(res_pop.recent_events) == 2

    # 4. Direct list_security_events call with filters
    dummy_user = User(id="dummy", username="admin", role="ADMIN", password_hash="pw")
    ev_list = await list_security_events(
        limit=10,
        offset=0,
        risk_level="CRITICAL",
        action="BLOCK",
        source_ip="127.0.0.1",
        db=test_db,
        _user=dummy_user,
    )
    assert ev_list.total == 1
    assert ev_list.events[0].risk_score == 95
