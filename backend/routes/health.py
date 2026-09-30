"""
SentinelGate — Health Check Route
===================================
Exposed at GET /health.
Nginx restricts this endpoint to 127.0.0.1 — it is never reachable
from the public internet.  The response intentionally leaks minimal
information (no stack versions, no DB details).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from backend.config import get_settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check (internal only)",
    include_in_schema=False,  # Hidden from public OpenAPI docs
)
async def health_check() -> HealthResponse:
    """
    Minimal liveness probe.

    Returns:
        - status: "ok"
        - version: application version string
        - timestamp: current UTC ISO timestamp

    Security note: This endpoint is bound to localhost only via Nginx.
    Do NOT include database connection info, dependency versions, or
    system information in this response.
    """
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
    )
