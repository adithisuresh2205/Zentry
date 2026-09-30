"""
SentinelGate — Test Configuration & Shared Fixtures
======================================================
All pytest fixtures used across the test suite are defined here.
Each test module can import fixtures by name without explicit imports.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
import pytest_asyncio
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.config import Settings, get_settings
from backend.database.session import Base, get_db
from backend.main import create_app


# ── Test settings override ────────────────────────────────────────────────────

TEST_SECRET_KEY = "a" * 64  # 64 chars = minimum valid key for tests
os.environ.setdefault("SECRET_KEY", TEST_SECRET_KEY)

def get_test_settings() -> Settings:
    """Return settings configured for the test environment."""
    return Settings(
        app_env="test",
        debug=True,
        log_level="DEBUG",
        secret_key=TEST_SECRET_KEY,
        database_url="sqlite+aiosqlite:///:memory:",
        redis_url="redis://localhost:6379/15",   # overridden by mock_redis fixture
        allowed_origins=["http://testclient"],
        rate_limit_requests=1000,               # relaxed in tests
        rate_limit_auth_requests=100,           # relaxed in tests to allow brute-force testing
        brute_force_block_threshold=10,         # 10 attempts
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provide a fresh in-memory SQLite database per test function.
    All tables are created before the test and dropped after.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    import backend.database.session as db_session  # noqa: PLC0415
    prev_factory = db_session._session_factory
    db_session._session_factory = session_factory

    try:
        async with session_factory() as session:
            yield session
    finally:
        db_session._session_factory = prev_factory
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def mock_redis() -> AsyncGenerator[FakeRedis, None]:
    """
    Provide an in-memory fake Redis instance per test.
    Isolates tests from production Redis state.
    """
    from backend.rate_limiter.limiter import reset_in_memory_rate_limits  # noqa: PLC0415
    reset_in_memory_rate_limits()
    redis = FakeRedis(decode_responses=True)
    yield redis
    await redis.flushall()
    await redis.aclose()
    reset_in_memory_rate_limits()


@pytest.fixture(autouse=True)
def reset_audit_state() -> Generator[None, None, None]:
    """Ensure clean AuditLogger state before and after every test."""
    from backend.audit.logger import reset_audit_logger  # noqa: PLC0415
    reset_audit_logger()
    yield
    reset_audit_logger()


@pytest_asyncio.fixture(scope="function")
async def async_client(
    test_db: AsyncSession,
    mock_redis: FakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Provide an async HTTP test client for the full FastAPI application.
    Database and Redis are replaced with test doubles.
    """
    # Override settings and env
    monkeypatch.setenv("SECRET_KEY", TEST_SECRET_KEY)
    monkeypatch.setattr("backend.config.get_settings", get_test_settings)


    # Override DB dependency
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield test_db

    # Override Redis
    import backend.cache.redis_client as redis_module  # noqa: PLC0415
    monkeypatch.setattr(redis_module, "_redis", mock_redis)

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db


    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://testclient",
    ) as client:
        yield client

    app.dependency_overrides.clear()


# ── Convenience fixtures (Phase 2) ───────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def admin_token(test_db: AsyncSession) -> str:
    """Return a valid ADMIN JWT for use in test requests."""
    from datetime import timedelta  # noqa: PLC0415
    from backend.auth.service import create_jwt_token, hash_password  # noqa: PLC0415
    from backend.database.models import User  # noqa: PLC0415

    admin = User(
        username="fixture_admin",
        password_hash=hash_password("AdminPass123!"),
        role="ADMIN",
        is_active=True,
    )
    test_db.add(admin)
    await test_db.commit()
    await test_db.refresh(admin)

    token, _ = create_jwt_token(
        user_id=admin.id,
        username=admin.username,
        role="ADMIN",
        token_type="access",
        expires_delta=timedelta(minutes=15),
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def analyst_token(test_db: AsyncSession) -> str:
    """Return a valid ANALYST JWT for use in test requests."""
    from datetime import timedelta  # noqa: PLC0415
    from backend.auth.service import create_jwt_token, hash_password  # noqa: PLC0415
    from backend.database.models import User  # noqa: PLC0415

    analyst = User(
        username="fixture_analyst",
        password_hash=hash_password("AnalystPass123!"),
        role="ANALYST",
        is_active=True,
    )
    test_db.add(analyst)
    await test_db.commit()
    await test_db.refresh(analyst)

    token, _ = create_jwt_token(
        user_id=analyst.id,
        username=analyst.username,
        role="ANALYST",
        token_type="access",
        expires_delta=timedelta(minutes=15),
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def user_token(test_db: AsyncSession) -> str:
    """Return a valid USER JWT for use in test requests."""
    from datetime import timedelta  # noqa: PLC0415
    from backend.auth.service import create_jwt_token, hash_password  # noqa: PLC0415
    from backend.database.models import User  # noqa: PLC0415

    user = User(
        username="fixture_user",
        password_hash=hash_password("UserPass123!"),
        role="USER",
        is_active=True,
    )
    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)

    token, _ = create_jwt_token(
        user_id=user.id,
        username=user.username,
        role="USER",
        token_type="access",
        expires_delta=timedelta(minutes=15),
    )
    return token
