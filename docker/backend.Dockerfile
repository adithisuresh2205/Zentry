# ─────────────────────────────────────────────────────────────────────────────
# SentinelGate — Backend Dockerfile
# Multi-stage build: build stage installs deps, runtime stage is lean.
# Runs as non-root user for security.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Install uv for fast dependency installation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /build

# Copy dependency files only (layer cache: only rebuilds if deps change)
COPY pyproject.toml ./

# Install all production dependencies into a virtual environment
RUN uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python \
    fastapi uvicorn[standard] httpx bcrypt "pyjwt[crypto]" \
    python-jose[cryptography] passlib[bcrypt] python-multipart \
    sqlalchemy[asyncio] asyncpg aiosqlite alembic \
    "redis[asyncio]" \
    pydantic pydantic-settings python-dotenv \
    structlog orjson python-dateutil

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: create non-root user
RUN groupadd --gid 1001 sentinel && \
    useradd --uid 1001 --gid sentinel --shell /bin/bash --create-home sentinel

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment to use venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app"

WORKDIR /app

# Copy application source
COPY backend/ ./backend/
COPY alembic.ini ./

# Change ownership to non-root user
RUN chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Health check (internal — Nginx enforces external restriction)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

# Expose application port (internal only)
EXPOSE 8000

# Run with uvicorn using multiple workers in production
CMD ["uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--access-log"]
