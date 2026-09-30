"""
SentinelGate — Gateway Pipeline & Security Middleware
======================================================
Executes the ordered Zero-Trust security pipeline for every incoming request:
1. Request ID injection (UUID4)
2. Payload size guard (HTTP 413)
3. Request timeout enforcement (HTTP 504)
4. Client IP extraction & IPv4/IPv6 normalization with anti-spoofing
5. CORS & origin inspection
6. Security checks dispatch (Phases 2–6)
7. Security response headers injection (HSTS, CSP, X-Frame-Options, X-Request-ID, etc.)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Awaitable, Callable

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.audit.logger import get_audit_logger
from backend.config import get_settings
from backend.network import extract_client_ip
from backend.schemas.context import CheckResult, GatewayContext

log = structlog.get_logger(__name__)

SecurityCheckCallable = Callable[[GatewayContext], Awaitable[CheckResult]]


def _record_audit_event(ctx: GatewayContext, status_code: int) -> None:
    """Helper to dispatch audit event logging safely without raising."""
    try:
        duration_ms = int((datetime.now(timezone.utc) - ctx.timestamp).total_seconds() * 1000)
        get_audit_logger().log_event(ctx, response_code=status_code, duration_ms=duration_ms)
    except Exception as exc:
        log.warn("gateway.audit_log_error", error=str(exc), request_id=ctx.request_id)



class GatewayPipeline:
    """
    Registry and executor of ordered security checks.
    Additional checks are registered in subsequent phases (auth, rate limiter, WAF, etc.).
    """

    def __init__(self) -> None:
        self._checks: list[tuple[str, SecurityCheckCallable]] = []

    def register_check(self, name: str, check: SecurityCheckCallable) -> None:
        """Register a security check into the evaluation pipeline."""
        self._checks.append((name, check))

    async def execute(self, ctx: GatewayContext) -> CheckResult:
        """
        Execute all registered security checks in sequence.
        Short-circuits immediately if a check fails (hard block).
        Accumulates risk score and threats for non-blocking signals.
        """
        for name, check in self._checks:
            try:
                res = await check(ctx)
                if res.risk_delta > 0:
                    ctx.add_risk(res.risk_delta)
                if res.threat:
                    ctx.threats.append(res.threat)
                if not res.passed:
                    ctx.decision = "BLOCK"
                    ctx.blocked_reason = res.block_reason or f"Blocked by check {name}"
                    ctx.response_status = res.status_code
                    return res
            except Exception as e:
                log.error("gateway.pipeline.check_error", check=name, error=str(e))
                # Fail-secure: unexpected error in security check triggers high risk / block
                ctx.add_risk(25)

        return CheckResult(passed=True)


def init_default_pipeline(target: GatewayPipeline | None = None) -> GatewayPipeline:
    """Register all active phase security checks into the pipeline."""
    p = target if target is not None else pipeline
    p._checks.clear()
    from backend.rate_limiter.ip_blocklist import ip_blocklist_check  # noqa: PLC0415
    from backend.rate_limiter.limiter import rate_limiting_check      # noqa: PLC0415
    from backend.threat_detection.engine import threat_detection_check  # noqa: PLC0415
    from backend.risk_engine.scorer import risk_scoring_check          # noqa: PLC0415
    from backend.policy.engine import policy_enforcement_check        # noqa: PLC0415

    p.register_check("ip_blocklist", ip_blocklist_check)
    p.register_check("rate_limiter", rate_limiting_check)
    p.register_check("threat_detection", threat_detection_check)
    p.register_check("risk_scoring", risk_scoring_check)
    p.register_check("policy_enforcement", policy_enforcement_check)
    return p


# Global pipeline instance
pipeline = GatewayPipeline()
init_default_pipeline(pipeline)


def apply_security_headers(response: Response, ctx: GatewayContext) -> None:
    """
    Inject hardened HTTP security headers to all responses (ALLOW and BLOCK).
    """
    headers = response.headers
    headers["X-Request-ID"] = ctx.request_id
    headers["X-Risk-Score"] = str(ctx.risk_score)
    headers["X-Risk-Level"] = ctx.risk_level

    # Security headers
    headers["X-Content-Type-Options"] = "nosniff"
    headers["X-Frame-Options"] = "DENY"
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"


class GatewayMiddleware(BaseHTTPMiddleware):
    """
    Top-level ASGI security gateway middleware.
    Intercepts every HTTP request before route handlers are invoked.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()

        # ── 1. Request ID Injection ───────────────────────────────────────────
        # Prefer existing X-Request-ID from upstream proxy if provided, else generate new UUID4
        incoming_req_id = request.headers.get("x-request-id")
        headers_dict = {k.lower(): v for k, v in request.headers.items()}

        # ── 2. Client IP Extraction & Normalization ───────────────────────────
        client_host = request.client.host if request.client else None
        client_ip, is_ipv6 = extract_client_ip(
            peer_ip=client_host,
            headers=headers_dict,
            trusted_proxies=settings.trusted_proxies,
        )

        # ── 3. Initialize GatewayContext ──────────────────────────────────────
        from uuid import uuid4  # noqa: PLC0415
        ctx = GatewayContext(
            request_id=incoming_req_id or str(uuid4()),
            client_ip=client_ip,
            is_ipv6=is_ipv6,
            method=request.method,
            path=request.url.path,
            query_string=request.url.query,
            user_agent=headers_dict.get("user-agent", ""),
            query_params=dict(request.query_params),
            headers=headers_dict,
        )

        request.state.gateway_context = ctx

        # Bypass security pipeline for internal health endpoint
        if ctx.path == "/health":
            response = await call_next(request)
            apply_security_headers(response, ctx)
            return response

        # ── 4. Payload Size Guard (Phase 1 Loophole fix) ───────────────────────
        content_length_header = headers_dict.get("content-length")
        if content_length_header:
            try:
                content_len = int(content_length_header)
                if content_len > settings.max_body_size_bytes:
                    ctx.decision = "BLOCK"
                    ctx.blocked_reason = "Payload size exceeds maximum allowed limit"
                    ctx.response_status = 413
                    ctx.add_risk(10)
                    resp = JSONResponse(
                        status_code=413,
                        content={
                            "status": "blocked",
                            "request_id": ctx.request_id,
                            "risk_score": ctx.risk_score,
                            "risk_level": ctx.risk_level,
                            "message": ctx.blocked_reason,
                        },
                    )
                    _record_audit_event(ctx, 413)
                    apply_security_headers(resp, ctx)
                    return resp
            except ValueError:
                pass

        # Read request body with streaming size enforcement
        body_bytes = b""
        total_read = 0
        async for chunk in request.stream():
            total_read += len(chunk)
            if total_read > settings.max_body_size_bytes:
                ctx.decision = "BLOCK"
                ctx.blocked_reason = "Streamed payload exceeds maximum allowed size"
                ctx.response_status = 413
                ctx.add_risk(10)
                resp = JSONResponse(
                    status_code=413,
                    content={
                        "status": "blocked",
                        "request_id": ctx.request_id,
                        "risk_score": ctx.risk_score,
                        "risk_level": ctx.risk_level,
                        "message": ctx.blocked_reason,
                    },
                )
                _record_audit_event(ctx, 413)
                apply_security_headers(resp, ctx)
                return resp
            body_bytes += chunk

        ctx.body = body_bytes
        # Cache body on Starlette request so downstream handlers receive it
        request._body = body_bytes
        request.state.gateway_context = ctx

        # ── 5. Execute Security Checks Pipeline ───────────────────────────────
        check_result = await pipeline.execute(ctx)
        if not check_result.passed:
            ctx.decision = "BLOCK"
            status_code = ctx.response_status or 403
            resp = JSONResponse(
                status_code=status_code,
                content={
                    "status": "blocked",
                    "request_id": ctx.request_id,
                    "risk_score": ctx.risk_score,
                    "risk_level": ctx.risk_level,
                    "threats": [t.category for t in ctx.threats],
                    "message": ctx.blocked_reason or "Request blocked by security policy",
                    "timestamp": ctx.timestamp.isoformat(),
                },
            )
            _record_audit_event(ctx, status_code)
            apply_security_headers(resp, ctx)
            return resp

        # ── 6. Request Timeout Enforcement (Phase 1 Loophole fix) ─────────────
        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=float(settings.request_timeout_seconds),
            )
        except asyncio.TimeoutError:
            ctx.decision = "BLOCK"
            ctx.blocked_reason = "Request execution timed out"
            ctx.response_status = 504
            ctx.add_risk(15)
            log.warn("gateway.timeout", request_id=ctx.request_id, ip=ctx.client_ip)
            resp = JSONResponse(
                status_code=504,
                content={
                    "status": "blocked",
                    "request_id": ctx.request_id,
                    "risk_score": ctx.risk_score,
                    "risk_level": ctx.risk_level,
                    "message": ctx.blocked_reason or "Request execution timed out",
                },
            )
            _record_audit_event(ctx, 504)
            apply_security_headers(resp, ctx)
            return resp

        # ── 7. Apply Security Headers & Return ────────────────────────────────
        _record_audit_event(ctx, response.status_code)
        apply_security_headers(response, ctx)
        return response
