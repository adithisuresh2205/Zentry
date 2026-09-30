"""
SentinelGate — Phase 4 WAF Integration Tests
============================================
Lean, targeted integration tests verifying WAF deep inspection
wired into the active GatewayPipeline and GatewayMiddleware:
- Primary happy path: clean traffic allowed through with security headers
- Main blocking condition: SQLi in query param and XSS in JSON body return 403
- Method abuse: disallowed HTTP method returns 405
- Edge case: double-encoded evasion attempts caught; legitimate punctuation allowed
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_waf_happy_path_clean_request_allowed(async_client: AsyncClient) -> None:
    """Clean legitimate request passes through WAF and receives security headers."""
    resp = await async_client.get(
        "/health",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    assert resp.status_code == 200
    assert "x-request-id" in resp.headers
    assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_waf_blocks_sqli_in_query_param(async_client: AsyncClient) -> None:
    """SQL injection in query parameter is intercepted and blocked with 403."""
    resp = await async_client.post(
        "/auth/login?search=%27%20OR%201%3D1%20--",
        json={"username": "validuser", "password": "ValidPassword123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["status"] == "blocked"
    assert "SQL_INJECTION" in data["threats"]
    assert "x-request-id" in resp.headers
    assert int(resp.headers.get("x-risk-score", 0)) >= 60


@pytest.mark.asyncio
async def test_waf_blocks_xss_in_json_body(async_client: AsyncClient) -> None:
    """XSS vector in JSON body field is intercepted and blocked with 403."""
    resp = await async_client.post(
        "/auth/login",
        json={"username": "<script>alert(document.cookie)</script>", "password": "Password123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["status"] == "blocked"
    assert "XSS" in data["threats"]


@pytest.mark.asyncio
async def test_waf_blocks_method_abuse_with_405(async_client: AsyncClient) -> None:
    """Disallowed HTTP method (GET on /auth/login) returns HTTP 405 Method Not Allowed."""
    resp = await async_client.get(
        "/auth/login",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 405
    data = resp.json()
    assert data["status"] == "blocked"
    assert "METHOD_ABUSE" in data["threats"]


@pytest.mark.asyncio
async def test_waf_catches_double_encoded_evasion(async_client: AsyncClient) -> None:
    """Double percent-encoded directory traversal is normalized and blocked."""
    resp = await async_client.post(
        "/auth/login?doc=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        json={"username": "testuser", "password": "Password123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["status"] == "blocked"
    assert "PATH_TRAVERSAL" in data["threats"]


@pytest.mark.asyncio
async def test_waf_allows_legitimate_special_characters(async_client: AsyncClient) -> None:
    """Names with apostrophes and search queries with mathematical symbols are allowed."""
    resp = await async_client.post(
        "/auth/login",
        json={"username": "john_o'brien", "password": "Password123!"},
        headers={"User-Agent": "Mozilla/5.0"},
    )
    # Reaches auth logic (e.g. 401 Unauthorized for bad credentials, NOT 403 WAF Block)
    assert resp.status_code == 401
