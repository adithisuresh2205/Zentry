"""
SentinelGate — Database Session
=================================
Provides an async SQLAlchemy engine and session factory.
Full ORM models and Alembic migrations are implemented in Phase 7.
This module exists in Phase 0 to satisfy the lifespan import.
"""
from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from backend.config import get_settings

log = structlog.get_logger(__name__)

# Module-level engine singleton (set during init_db)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


class Base(DeclarativeBase):
    """
    SQLAlchemy declarative base.
    All ORM models must inherit from this class.
    """
    pass


async def init_db() -> None:
    """
    Initialise the database engine and create tables.
    Called once at application startup.

    In production: Alembic handles schema migrations.
    In development/test: create_all() is used for convenience.
    """
    global _engine, _session_factory

    settings = get_settings()

    _engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_pre_ping=True,       # Detect stale connections
        pool_size=10,             # Max 10 persistent connections
        max_overflow=20,          # Up to 20 overflow connections
        connect_args=(
            {}
            if "postgresql" in settings.database_url
            else {"check_same_thread": False}  # SQLite dev/test only
        ),
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # In non-production environments, create tables if they don't exist.
    # Production uses Alembic migrations exclusively.
    if not settings.is_production:
        async with _engine.begin() as conn:
            # Import all models here so Base.metadata knows about them
            # (Models are created in Phase 7; import is harmless if absent)
            try:
                from backend.database import models as _models  # noqa: F401, PLC0415
                await conn.run_sync(Base.metadata.create_all)
                log.info("sentinelgate.database.tables_created")
            except ImportError:
                log.info("sentinelgate.database.models_not_yet_implemented")

    log.info("sentinelgate.database.connected", url=_mask_url(settings.database_url))


async def close_db() -> None:
    """Dispose of the database engine. Called at application shutdown."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        log.info("sentinelgate.database.disconnected")


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Return the global async session factory.
    Raises RuntimeError if called before init_db().
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _session_factory


async def get_db() -> AsyncSession:  # type: ignore[return]
    """
    FastAPI dependency that yields an AsyncSession per request.

    Usage:
        @router.get("/example")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            ...
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def _mask_url(url: str) -> str:
    """Mask the password in a database URL for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse  # noqa: PLC0415
        parsed = urlparse(url)
        if parsed.password:
            masked = parsed._replace(
                netloc=parsed.netloc.replace(parsed.password, "***")
            )
            return urlunparse(masked)
    except Exception:
        pass
    return "<database-url>"
