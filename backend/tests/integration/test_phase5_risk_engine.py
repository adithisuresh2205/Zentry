"""
SentinelGate — Phase 5 Risk Engine Integration Tests
====================================================
Lean, targeted integration tests verifying end-to-end multi-signal risk calculation
and header propagation through GatewayMiddleware and GatewayPipeline:
- Happy path: Clean request has score 0 and LOW risk
- Elevated context signal: Scanner User-Agent updates risk score in response headers
- Multi-vector compound attack: Triggered compound bonus and CRITICAL risk
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_risk_scorer_happy_path_clean_request(async_client: AsyncClient) -> None:
    """Clean legitimate request reflects score 0 and LOW risk level in headers."""
    resp = await async_client.get(
        "/health",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-risk-score") == "0"
    assert resp.headers.get("x-risk-level") == "LOW"


@pytest.mark.asyncio
async def test_risk_scorer_scanner_ua_reflects_elevated_risk(async_client: AsyncClient) -> None:
    """Automated security scanner increases risk score via context signals."""
    resp = await async_client.get(
        "/auth/me",
        headers={"User-Agent": "sqlmap/1.7#stable"},
    )
    # Reaches auth check (401 because unauthenticated, but risk score was evaluated)
    assert resp.status_code == 401
    assert int(resp.headers.get("x-risk-score", 0)) >= 25
    assert resp.headers.get("x-risk-level") in ["LOW", "MEDIUM"]


@pytest.mark.asyncio
async def test_risk_scorer_compound_attack_escalates_to_critical(async_client: AsyncClient) -> None:
    """Compound attack (SQLi + XSS) triggers compound multiplier and yields CRITICAL risk."""
    resp = await async_client.post(
        "/auth/login?q=%27%20OR%201%3D1%20--",
        json={"username": "<script>alert(1)</script>", "password": "Password123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["status"] == "blocked"
    assert data["risk_score"] >= 80
    assert data["risk_level"] == "CRITICAL"
    assert resp.headers.get("x-risk-level") == "CRITICAL"
