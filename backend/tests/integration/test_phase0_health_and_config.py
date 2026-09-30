"""
Phase 0 — Integration Tests: Health Endpoint & Configuration
=============================================================
Verifies the application starts correctly and the health endpoint
returns the expected minimal response without leaking system info.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestHealthEndpoint:
    """Tests for GET /health."""

    async def test_health_returns_200(self, async_client: AsyncClient) -> None:
        """Health endpoint must return HTTP 200."""
        response = await async_client.get("/health")
        assert response.status_code == 200

    async def test_health_returns_ok_status(self, async_client: AsyncClient) -> None:
        """Health response body must contain status=ok."""
        response = await async_client.get("/health")
        data = response.json()
        assert data["status"] == "ok"

    async def test_health_returns_version(self, async_client: AsyncClient) -> None:
        """Health response must include application version."""
        response = await async_client.get("/health")
        data = response.json()
        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    async def test_health_returns_timestamp(self, async_client: AsyncClient) -> None:
        """Health response must include a UTC ISO timestamp."""
        response = await async_client.get("/health")
        data = response.json()
        assert "timestamp" in data
        # Must be parseable ISO format
        from datetime import datetime  # noqa: PLC0415
        dt = datetime.fromisoformat(data["timestamp"])
        assert dt is not None

    async def test_health_does_not_leak_system_info(
        self, async_client: AsyncClient
    ) -> None:
        """Health response must NOT contain db URL, redis URL, or internal paths."""
        response = await async_client.get("/health")
        body = response.text.lower()
        forbidden = ["postgresql", "sqlite", "redis", "secret", "password", "/home", "/usr"]
        for term in forbidden:
            assert term not in body, f"Health response leaks sensitive term: {term!r}"

    async def test_health_not_in_openapi(self, async_client: AsyncClient) -> None:
        """Health endpoint must be excluded from the OpenAPI schema."""
        response = await async_client.get("/openapi.json")
        if response.status_code == 200:
            schema = response.json()
            paths = schema.get("paths", {})
            assert "/health" not in paths, "Health endpoint must not appear in OpenAPI docs"


class TestConfiguration:
    """Tests for the settings / configuration system."""

    def test_settings_secret_key_too_short_raises(self) -> None:
        """Settings must reject a SECRET_KEY shorter than 64 characters."""
        from pydantic import ValidationError  # noqa: PLC0415
        from backend.config import Settings  # noqa: PLC0415
        import pytest  # noqa: PLC0415
        with pytest.raises((ValidationError, ValueError)):
            Settings(secret_key="short")  # type: ignore[call-arg]

    def test_settings_placeholder_secret_key_raises(self) -> None:
        """Settings must reject the placeholder SECRET_KEY from .env.example."""
        from pydantic import ValidationError  # noqa: PLC0415
        from backend.config import Settings  # noqa: PLC0415
        with pytest.raises((ValidationError, ValueError)):
            Settings(secret_key="REPLACE_WITH_256_BIT_RANDOM_HEX_STRING")  # type: ignore[call-arg]

    def test_settings_valid_secret_key_accepted(self) -> None:
        """Settings must accept a 64-character hexadecimal SECRET_KEY."""
        import secrets  # noqa: PLC0415
        from backend.config import Settings  # noqa: PLC0415
        valid_key = secrets.token_hex(32)  # 64 hex chars
        settings = Settings(secret_key=valid_key)  # type: ignore[call-arg]
        assert settings.secret_key == valid_key

    def test_settings_risk_thresholds_ordered(self) -> None:
        """Risk thresholds must be strictly ascending."""
        from backend.tests.conftest import get_test_settings as ts  # noqa: PLC0415
        settings = ts()
        assert settings.risk_threshold_medium < settings.risk_threshold_high
        assert settings.risk_threshold_high < settings.risk_threshold_critical

    def test_get_settings_returns_singleton(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_settings() must return the same instance on repeated calls."""
        import secrets  # noqa: PLC0415
        from backend.config import Settings, get_settings  # noqa: PLC0415
        monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
        get_settings.cache_clear()
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
        get_settings.cache_clear()

