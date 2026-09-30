"""
SentinelGate — Phase 6 Policy Engine Integration Tests
======================================================
Lean, targeted integration tests verifying:
- Happy path: Clean request allowed with security headers injected
- Main blocking condition: Blocked response schema with ISO timestamp and threat metadata
- Allowlist relief: Allowlisted IP bypasses WAF threat block
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from backend.config import get_settings


@pytest.mark.asyncio
async def test_policy_happy_path_with_security_headers(async_client: AsyncClient) -> None:
    """Clean request flows through, receives 200, and includes all security headers."""
    resp = await async_client.get(
        "/health",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 200
    # Mandatory security response headers
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "Strict-Transport-Security" in resp.headers or "strict-transport-security" in resp.headers
    assert "Content-Security-Policy" in resp.headers or "content-security-policy" in resp.headers
    assert "x-request-id" in resp.headers


@pytest.mark.asyncio
async def test_policy_blocked_response_schema_conformance(async_client: AsyncClient) -> None:
    """Blocked request returns standard JSON schema with timestamp and threat metadata."""
    resp = await async_client.post(
        "/auth/login?search=%27%20OR%201%3D1%20--",
        json={"username": "attacker", "password": "Password123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 403
    data = resp.json()
    # Conformance to Master Plan Blocked Response Schema
    assert data["status"] == "blocked"
    assert "request_id" in data
    assert "risk_score" in data
    assert data["risk_score"] >= 60
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert "SQL_INJECTION" in data["threats"]
    assert "message" in data
    assert "timestamp" in data

    # Headers also present on blocked response
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"


@pytest.mark.asyncio
async def test_policy_allowlist_ip_bypasses_threat_block(
    async_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backend.tests.conftest as conftest_module
    test_settings = conftest_module.get_test_settings()
    test_settings.waf_allowlist_ips = ["127.0.0.1"]
    monkeypatch.setattr("backend.threat_detection.engine.get_settings", lambda: test_settings)
    monkeypatch.setattr("backend.policy.engine.get_settings", lambda: test_settings)
    monkeypatch.setattr("backend.config.get_settings", lambda: test_settings)

    resp = await async_client.post(
        "/auth/login?q=%27%20OR%201%3D1%20--",
        json={"username": "valid_user", "password": "WrongPassword123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    # Reaches auth endpoint instead of 403 WAF block
    assert resp.status_code == 401
