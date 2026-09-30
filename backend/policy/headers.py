"""
SentinelGate — Security Headers Management
==========================================
Hardens all outgoing HTTP responses (both ALLOW and BLOCK) with OWASP-recommended
security headers and telemetry metadata.
"""
from __future__ import annotations

from fastapi import Response

from backend.schemas.context import GatewayContext

# Standard hardened HTTP security headers
DEFAULT_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
}


def apply_security_headers(response: Response, ctx: GatewayContext) -> None:
    """
    Inject hardened HTTP security headers and correlation telemetry
    to all responses (ALLOW, BLOCK, error, or health).
    """
    headers = response.headers

    # 1. Telemetry and Traceability
    headers["X-Request-ID"] = ctx.request_id
    headers["X-Risk-Score"] = str(ctx.risk_score)
    headers["X-Risk-Level"] = ctx.risk_level

    # 2. Defensive HTTP Security Headers
    for header_name, header_value in DEFAULT_SECURITY_HEADERS.items():
        headers[header_name] = header_value
