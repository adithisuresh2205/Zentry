"""
Phase 1 — Integration Tests: Core Gateway Middleware Pipeline
=============================================================
Verifies:
1. Request ID injection (X-Request-ID present on response & preserved if sent)
2. Payload size guard enforcement (413 Payload Too Large)
3. Request timeout enforcement (504 Gateway Timeout)
4. Security response headers present on both ALLOW and BLOCK responses
5. GatewayContext attached to request state and accessible
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest
import pytest_asyncio
from fastapi import APIRouter, Request
from httpx import AsyncClient


from backend.main import create_app
from backend.schemas.context import GatewayContext

# Helper router for testing middleware behavior
test_router = APIRouter(prefix="/test")


@test_router.get("/ping")
async def ping(request: Request) -> dict[str, Any]:
    ctx: GatewayContext = request.state.gateway_context
    return {
        "status": "pong",
        "request_id": ctx.request_id,
        "client_ip": ctx.client_ip,
        "risk_score": ctx.risk_score,
        "risk_level": ctx.risk_level,
    }


@test_router.post("/echo")
async def echo(request: Request) -> dict[str, Any]:
    ctx: GatewayContext = request.state.gateway_context
    body = await request.body()
    return {
        "body_len": len(body),
        "request_id": ctx.request_id,
    }


@test_router.get("/slow")
async def slow_endpoint() -> dict[str, str]:
    # Sleep longer than the configured timeout
    await asyncio.sleep(2.0)
    return {"status": "too late"}


class TestGatewayMiddlewarePipeline:
    """Integration tests verifying the GatewayMiddleware end-to-end."""

    @pytest_asyncio.fixture
    async def pipeline_client(
        self,
        test_db: Any,
        mock_redis: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> AsyncClient:
        """Create a client with strict test settings (1KB payload, 1s timeout)."""
        from httpx import ASGITransport
        from backend.config import Settings
        from backend.database.session import get_db
        from backend.tests.conftest import TEST_SECRET_KEY

        def get_custom_test_settings() -> Settings:
            return Settings(
                app_env="test",
                debug=True,
                log_level="DEBUG",
                secret_key=TEST_SECRET_KEY,
                database_url="sqlite+aiosqlite:///:memory:",
                redis_url="redis://localhost:6379/15",
                allowed_origins=["http://testclient"],
                max_body_size_bytes=1024,      # 1 KB limit for tests
                request_timeout_seconds=1,     # 1 second timeout for tests
            )

        monkeypatch.setenv("SECRET_KEY", TEST_SECRET_KEY)
        monkeypatch.setattr("backend.config.get_settings", get_custom_test_settings)
        monkeypatch.setattr("backend.gateway.get_settings", get_custom_test_settings)
        monkeypatch.setattr("backend.main.get_settings", get_custom_test_settings)


        async def override_get_db() -> Any:
            yield test_db

        import backend.cache.redis_client as redis_module
        monkeypatch.setattr(redis_module, "_redis", mock_redis)

        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        app.include_router(test_router)

        async with AsyncClient(
            transport=ASGITransport(app=app),  # type: ignore[arg-type]
            base_url="http://testclient",
        ) as client:
            yield client

    async def test_request_id_injected_and_returned_in_header(
        self, pipeline_client: AsyncClient
    ) -> None:
        """Every request must receive an X-Request-ID response header."""
        response = await pipeline_client.get("/test/ping")
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        req_id = response.headers["X-Request-ID"]
        assert len(req_id) > 10

    async def test_incoming_request_id_preserved(
        self, pipeline_client: AsyncClient
    ) -> None:
        """If client/proxy sends X-Request-ID, the gateway must preserve it."""
        custom_id = "test-corr-uuid-12345"
        response = await pipeline_client.get("/test/ping", headers={"X-Request-ID": custom_id})
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_id
        assert response.json()["request_id"] == custom_id

    async def test_security_headers_present_on_allow(
        self, pipeline_client: AsyncClient
    ) -> None:
        """Allowed responses must include HSTS, CSP, X-Frame-Options, X-Content-Type-Options."""
        response = await pipeline_client.get("/test/ping")
        assert response.status_code == 200
        headers = response.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in headers
        assert "Strict-Transport-Security" in headers
        assert "X-Risk-Score" in headers
        assert "X-Risk-Level" in headers

    async def test_payload_size_limit_by_header(
        self, pipeline_client: AsyncClient
    ) -> None:
        """Requests with Content-Length greater than max_body_size_bytes must be rejected with 413."""
        headers = {
            "Content-Length": "2048",  # limit in fixture is 1024
            "Content-Type": "application/json",
        }
        response = await pipeline_client.post("/test/echo", headers=headers, content=b"x" * 2048)
        assert response.status_code == 413
        data = response.json()
        assert data["status"] == "blocked"
        assert "Payload size" in data["message"]
        # Must still include security headers and correlation ID
        assert "X-Request-ID" in response.headers
        assert response.headers.get("X-Frame-Options") == "DENY"

    async def test_streamed_payload_size_limit_rejection(
        self, pipeline_client: AsyncClient
    ) -> None:
        """Streamed payloads exceeding max limit without Content-Length header must trigger 413."""
        # Send 2 KB without Content-Length
        response = await pipeline_client.post("/test/echo", content=b"A" * 2048)
        assert response.status_code == 413
        data = response.json()
        assert data["status"] == "blocked"

    async def test_pipeline_blocking_check_returns_403(
        self, pipeline_client: AsyncClient
    ) -> None:
        """When a registered security check blocks, the gateway returns a 403 response."""
        from backend.gateway import pipeline
        from backend.schemas.context import CheckResult, GatewayContext, ThreatMatch

        async def malicious_block(ctx: GatewayContext) -> CheckResult:
            if ctx.path == "/test/blocked":
                threat = ThreatMatch(
                    rule_id="TEST_BLOCK",
                    category="MALICIOUS",
                    severity="CRITICAL",
                    risk_delta=85,
                )
                return CheckResult(
                    passed=False,
                    risk_delta=85,
                    threat=threat,
                    block_reason="Explicitly blocked by test check",
                    status_code=403,
                )
            return CheckResult(passed=True)

        pipeline.register_check("test_blocker", malicious_block)
        try:
            response = await pipeline_client.get("/test/blocked")
            assert response.status_code == 403
            data = response.json()
            assert data["status"] == "blocked"
            assert "MALICIOUS" in data["threats"]
            assert data["risk_score"] == 85
            assert data["risk_level"] == "CRITICAL"
            assert response.headers.get("X-Frame-Options") == "DENY"
        finally:
            pipeline._checks = [c for c in pipeline._checks if c[0] != "test_blocker"]

    async def test_request_timeout_enforcement(
        self, pipeline_client: AsyncClient
    ) -> None:
        """Endpoints that hang past request_timeout_seconds must abort with 504 Gateway Timeout."""
        response = await pipeline_client.get("/test/slow")
        assert response.status_code == 504
        data = response.json()
        assert data["status"] == "blocked"
        assert "timed out" in data["message"].lower()
        assert "X-Request-ID" in response.headers
        assert response.headers.get("X-Frame-Options") == "DENY"




