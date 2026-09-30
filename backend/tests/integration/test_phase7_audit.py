"""
Integration tests for Phase 7 — Audit Logging & Database Layer
==============================================================
Tests:
1. Happy path: End-to-end blocked request creates DB security event with HMAC, queryable via /security/events.
2. Tamper verification: /security/integrity/verify validates untampered chain and flags tampered database records.
3. RBAC checks: /security/events accessible by ADMIN and ANALYST, forbidden to USER.
               /security/integrity/verify accessible ONLY by ADMIN.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.audit.logger import get_audit_logger
from backend.database.models import SecurityEvent, User


@pytest.mark.asyncio
async def test_end_to_end_audit_logging_and_events_query(
    async_client: AsyncClient,
    admin_token: str,
    test_db: AsyncSession,
) -> None:
    """A blocked attack request is recorded in DB and queryable via /security/events."""
    logger = get_audit_logger()
    logger.start()

    # Send a malicious request triggering SQLi block
    attack_payload = {"username": "admin' OR 1=1 --", "password": "Password123!"}
    res = await async_client.post(
        "/auth/login",
        json=attack_payload,
        headers={"User-Agent": "AttackClient/1.0"},
    )
    assert res.status_code == 403
    req_id = res.headers.get("X-Request-ID")
    assert req_id is not None

    # Allow worker to persist queued event
    await logger.flush()

    # Query /security/events as ADMIN
    events_res = await async_client.get(
        "/security/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert events_res.status_code == 200
    data = events_res.json()
    assert data["total"] >= 1

    matched = [e for e in data["events"] if e["request_id"] == req_id]
    assert len(matched) == 1
    event = matched[0]
    assert event["action"] == "BLOCK"
    assert event["risk_score"] >= 60
    assert event["response_code"] == 403
    assert event["hmac_chain"] is not None
    assert len(event["threats"]) > 0


@pytest.mark.asyncio
async def test_cryptographic_integrity_verification_and_tampering(
    async_client: AsyncClient,
    admin_token: str,
    test_db: AsyncSession,
) -> None:
    """Integrity endpoint confirms valid chain, and flags records modified directly in DB."""
    logger = get_audit_logger()
    logger.start()

    # 1. Trigger an attack request to create a clean logged event
    res = await async_client.get("/auth/me?q=%27%20OR%201%3D1--")
    assert res.status_code in (401, 403)
    await logger.flush()

    # 2. Check initial verification status -> must be verified
    verify_res1 = await async_client.get(
        "/security/integrity/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert verify_res1.status_code == 200
    data1 = verify_res1.json()
    assert data1["verified"] is True
    assert data1["tampered_events"] == []

    # 3. Simulate database tampering (malicious insider updates risk_score)
    stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(1)
    ev_res = await test_db.execute(stmt)
    latest_event = ev_res.scalar_one_or_none()
    assert latest_event is not None

    await test_db.execute(
        update(SecurityEvent)
        .where(SecurityEvent.id == latest_event.id)
        .values(risk_score=0)
    )
    await test_db.commit()

    # 4. Check verification status -> must now report compromised
    verify_res2 = await async_client.get(
        "/security/integrity/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert verify_res2.status_code == 200
    data2 = verify_res2.json()
    assert data2["verified"] is False
    assert len(data2["tampered_events"]) >= 1
    assert data2["tampered_events"][0]["request_id"] == latest_event.request_id


@pytest.mark.asyncio
async def test_security_routes_rbac_permissions(
    async_client: AsyncClient,
    admin_token: str,
    analyst_token: str,
    user_token: str,
) -> None:
    """Test RBAC access control for /security endpoints."""
    # /security/events: ADMIN and ANALYST allowed, USER forbidden
    res_admin = await async_client.get(
        "/security/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin.status_code == 200

    res_analyst = await async_client.get(
        "/security/events",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_analyst.status_code == 200

    res_user = await async_client.get(
        "/security/events",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res_user.status_code == 403

    # /security/integrity/verify: ADMIN allowed, ANALYST and USER forbidden
    res_verify_admin = await async_client.get(
        "/security/integrity/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_verify_admin.status_code == 200

    res_verify_analyst = await async_client.get(
        "/security/integrity/verify",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_verify_analyst.status_code == 403

    res_verify_user = await async_client.get(
        "/security/integrity/verify",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res_verify_user.status_code == 403


@pytest.mark.asyncio
async def test_security_stats_telemetry_endpoint(
    async_client: AsyncClient,
    admin_token: str,
    test_db: AsyncSession,
) -> None:
    """Test /security/stats aggregated telemetry computation and filtered events query."""
    logger = get_audit_logger()
    logger.start()

    # 1. Query /security/stats on empty or initial DB
    initial_stats_res = await async_client.get("/security/stats")
    assert initial_stats_res.status_code == 200

    # 2. Trigger simulated traffic with different threat levels
    await async_client.get("/api/products")
    await async_client.get("/api/search?q=%27%20OR%201%3D1--")
    await async_client.get("/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
    await logger.flush()

    # 3. Query /security/stats with populated data
    stats_res = await async_client.get("/security/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()

    assert "total_requests" in stats
    assert "allowed_requests" in stats
    assert "blocked_requests" in stats
    assert "challenged_requests" in stats
    assert "active_threats" in stats
    assert stats["global_threat_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert isinstance(stats["average_risk_score"], int)
    assert len(stats["threat_distribution"]) >= 6
    assert len(stats["traffic_timeline"]) >= 1
    assert isinstance(stats["recent_events"], list)

    # 4. Test query filters on /security/events
    filter_risk = await async_client.get(
        "/security/events?risk_level=HIGH",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert filter_risk.status_code == 200

    filter_action = await async_client.get(
        "/security/events?action=BLOCK",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert filter_action.status_code == 200

    filter_ip = await async_client.get(
        "/security/events?source_ip=127.0.0.1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert filter_ip.status_code == 200

