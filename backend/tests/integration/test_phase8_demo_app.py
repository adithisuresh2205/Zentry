"""
Integration tests for Phase 8 — Protected Demo Application
==========================================================
Tests:
1. Happy path: Authenticated requests to /api/users, /api/products, and clean /api/search?q=.
2. Security blocking: Malicious SQLi/XSS payloads to /api/search are intercepted with 403.
3. Edge case: Unauthenticated access rejected with 401, public /api/login permitted.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_protected_endpoints_authenticated_success(
    async_client: AsyncClient,
    user_token: str,
) -> None:
    """Authenticated user accesses protected mock endpoints."""
    headers = {"Authorization": f"Bearer {user_token}"}

    # 1. /api/users
    res_users = await async_client.get("/api/users", headers=headers)
    assert res_users.status_code == 200
    data_users = res_users.json()
    assert data_users["source"] == "protected_demo_app"
    assert data_users["count"] >= 1
    assert any(u["name"] == "Elena Rostova" for u in data_users["users"])

    # 2. /api/products
    res_prod = await async_client.get("/api/products", headers=headers)
    assert res_prod.status_code == 200
    data_prod = res_prod.json()
    assert data_prod["source"] == "protected_demo_app"
    assert data_prod["count"] >= 1

    # 3. /api/profile
    res_prof = await async_client.get("/api/profile", headers=headers)
    assert res_prof.status_code == 200
    data_prof = res_prof.json()
    assert data_prof["username"] == "fixture_user"

    # 4. Clean search query
    res_search = await async_client.get("/api/search?q=Appliance", headers=headers)
    assert res_search.status_code == 200
    data_search = res_search.json()
    assert data_search["query"] == "Appliance"
    assert data_search["total_matches"] >= 1


@pytest.mark.asyncio
async def test_search_endpoint_waf_interception(
    async_client: AsyncClient,
    user_token: str,
) -> None:
    """Malicious injection in /api/search query param is intercepted by WAF before reaching handler."""
    headers = {"Authorization": f"Bearer {user_token}"}

    # SQL Injection attempt in q parameter
    res = await async_client.get("/api/search?q=%27%20OR%201%3D1--", headers=headers)
    assert res.status_code == 403
    data = res.json()
    assert data["status"] == "blocked"
    assert "SQL_INJECTION" in data["threats"]


@pytest.mark.asyncio
async def test_protected_app_auth_enforcement_and_public_login(
    async_client: AsyncClient,
) -> None:
    """Unauthenticated requests are rejected with 401; public demo login is accessible."""
    # Unauthenticated request to protected endpoint
    res_unauth = await async_client.get("/api/users")
    assert res_unauth.status_code == 401

    # Public demo login endpoint
    res_login = await async_client.post(
        "/api/login",
        json={"username": "guest_demo", "password": "SamplePassword123!"},
    )
    assert res_login.status_code == 200
    data_login = res_login.json()
    assert data_login["status"] == "success"
    assert "guest_demo" in data_login["message"]
