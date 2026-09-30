"""
SentinelGate — Application Entry Point
=======================================
Bootstraps the FastAPI application, registers middleware, routes,
and lifecycle hooks.  All security modules are initialised here.
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from backend.config import get_settings

# ── Logger ────────────────────────────────────────────────────────────────────
log = structlog.get_logger(__name__)


# ── Application lifecycle ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Startup / shutdown lifecycle handler.
    On startup: validate config, connect to DB and Redis.
    On shutdown: gracefully close all connections.
    """
    settings = get_settings()

    log.info(
        "sentinelgate.startup",
        name=settings.app_name,
        version=settings.app_version,
        env=settings.app_env,
    )

    # ── Deferred imports (avoid circular imports at module load time) ──────────
    from backend.database.session import init_db, close_db          # noqa: PLC0415
    from backend.cache.redis_client import init_redis, close_redis  # noqa: PLC0415
    from backend.audit.logger import get_audit_logger               # noqa: PLC0415

    # ── Initialize database ───────────────────────────────────────────────────
    await init_db()
    log.info("sentinelgate.database.ready")

    # ── Initialize Redis ──────────────────────────────────────────────────────
    await init_redis()
    log.info("sentinelgate.redis.ready")

    # ── Initialize Audit Logger ───────────────────────────────────────────────
    audit_logger = get_audit_logger()
    audit_logger.start()
    log.info("sentinelgate.audit.ready")

    log.info("sentinelgate.ready", message="SentinelGate is operational.")

    yield  # ── Application runs here ─────────────────────────────────────────

    # ── Shutdown ──────────────────────────────────────────────────────────────
    log.info("sentinelgate.shutdown", message="Shutting down gracefully...")
    await audit_logger.stop()
    await close_db()
    await close_redis()
    log.info("sentinelgate.shutdown.complete")


# ── Factory ───────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """
    Application factory.  Returns a fully configured FastAPI instance.
    All middleware is registered in the correct order (outermost → innermost).
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Zero-Trust Web Application Security Gateway",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Middleware stack (registered bottom-up; executes top-down) ────────────
    _register_middleware(app, settings)

    # ── Routers ───────────────────────────────────────────────────────────────
    _register_routes(app)

    return app


def _register_middleware(app: FastAPI, settings: "Settings") -> None:  # type: ignore[name-defined]  # noqa: F821
    """Register all middleware in the correct execution order."""
    from backend.config import Settings  # noqa: PLC0415

    # 1. Trusted host (outermost) — reject requests with invalid Host header
    if settings.is_production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["localhost", "127.0.0.1", "gateway", "host.docker.internal", "*.sentinelgate.local", "*"],
        )

    # 2. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Risk-Score", "X-Risk-Level"],
    )

    # 3. SentinelGate Core Security Gateway Middleware (Phase 1)
    from backend.gateway import GatewayMiddleware  # noqa: PLC0415
    app.add_middleware(GatewayMiddleware)



def _register_routes(app: FastAPI) -> None:
    """Register all API routers."""
    from backend.routes.health import router as health_router  # noqa: PLC0415

    # ── Health (internal only — Nginx restricts externally) ───────────────────
    app.include_router(health_router, prefix="", tags=["Health"])

    # ── Authentication & RBAC (Phase 2) ───────────────────────────────────────
    from backend.routes.auth import router as auth_router  # noqa: PLC0415
    app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

    # ── Security & Audit (Phase 7) ───────────────────────────────────────────
    from backend.routes.security import router as security_router  # noqa: PLC0415
    app.include_router(security_router, prefix="/security", tags=["Security"])

    # ── Protected Demo Application (Phase 8) ─────────────────────────────────
    from backend.routes.app import router as app_router  # noqa: PLC0415
    app.include_router(app_router, prefix="/api", tags=["Protected Application"])

    # ── WebSocket Live Security Feed (Phase 10) ──────────────────────────────
    from backend.routes.ws import router as ws_router  # noqa: PLC0415
    app.include_router(ws_router, prefix="", tags=["WebSocket Live Feed"])


# ── Entry point ───────────────────────────────────────────────────────────────

def get_app() -> FastAPI:
    return create_app()


try:
    app = create_app()
except Exception as exc:
    import traceback
    traceback.print_exc()
    app = None  # type: ignore[assignment]


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",  # noqa: S104 — binding is controlled by Docker/Nginx
        port=8000,
        reload=get_settings().app_env == "development",
        log_level=get_settings().log_level.lower(),
        access_log=True,
    )
