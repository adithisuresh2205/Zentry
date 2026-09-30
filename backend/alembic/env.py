"""
SentinelGate — Alembic Environment
=====================================
Configures Alembic for async SQLAlchemy migrations.
Reads DATABASE_URL from the application settings (which reads .env).
"""
from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# ── Import app components ─────────────────────────────────────────────────────
from backend.config import get_settings
from backend.database.session import Base

# ── Alembic Config object ─────────────────────────────────────────────────────
config = context.config

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Override sqlalchemy.url from app settings ─────────────────────────────────
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)

# ── Target metadata (all models must be imported before this) ─────────────────
# Import all models here so Alembic can detect schema changes.
# Models are created in Phase 7. The try/except allows Phase 0 to function.
try:
    from backend.database import models as _models  # noqa: F401
except ImportError:
    pass

target_metadata = Base.metadata


# ── Offline migration (no live DB connection) ─────────────────────────────────

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode — generate SQL script without connecting.
    Useful for reviewing changes before applying them.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online migration (async, live DB connection) ──────────────────────────────

def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        include_schemas=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations against a live database using async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations."""
    asyncio.run(run_async_migrations())


# ── Dispatch ──────────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
