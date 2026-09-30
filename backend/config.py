"""
SentinelGate — Application Configuration
=========================================
All settings are loaded from environment variables (via .env for development).
The application will REFUSE TO START if critical security settings are missing
or insufficient (e.g., SECRET_KEY entropy too low).
"""
from __future__ import annotations

import secrets
import sys
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _ROOT_DIR / ".env"


class Settings(BaseSettings):
    """
    Central settings object.  Import and use `get_settings()` throughout the app.
    All values are read from environment variables or .env file.
    """

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "SentinelGate"
    app_version: str = "0.1.0"
    app_env: Literal["development", "production", "test"] = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # ── Security (CRITICAL) ───────────────────────────────────────────────────
    secret_key: str = Field(..., min_length=64)   # 64 hex chars = 256-bit minimum
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinelgate_dev.db",
        description="Async SQLAlchemy connection URL",
    )

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── CORS ──────────────────────────────────────────────────────────────────
    allowed_origins: list[str] | str = ["http://localhost:3000", "https://localhost"]

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    rate_limit_auth_requests: int = 10
    rate_limit_auth_window_seconds: int = 60
    rate_limit_api_requests: int = 200
    rate_limit_security_requests: int = 50

    # ── Brute-Force Protection ────────────────────────────────────────────────
    brute_force_warn_threshold: int = 5
    brute_force_block_threshold: int = 10
    brute_force_extended_threshold: int = 20
    brute_force_block_ttl_seconds: int = 900      # 15 min
    brute_force_extended_ttl_seconds: int = 3600  # 1 hour

    # ── Payload Limits ────────────────────────────────────────────────────────
    max_body_size_bytes: int = 1_048_576   # 1 MB
    request_timeout_seconds: int = 30

    # ── Threat Detection / WAF ────────────────────────────────────────────────
    waf_enabled: bool = True
    waf_block_threats: bool = True
    waf_allowlist_ips: list[str] = []
    waf_allowlist_paths: list[str] = []

    # ── Proxy & Network ───────────────────────────────────────────────────────
    trusted_proxies: list[str] = [
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]


    # ── Risk Scoring Thresholds ───────────────────────────────────────────────
    risk_threshold_medium: int = 30
    risk_threshold_high: int = 60
    risk_threshold_critical: int = 80

    # ── Frontend ──────────────────────────────────────────────────────────────
    next_public_api_url: str = "http://localhost:8000"
    next_public_ws_url: str = "ws://localhost:8000"

    # ─────────────────────────────────────────────────────────────────────────
    # Validators
    # ─────────────────────────────────────────────────────────────────────────

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """
        Enforce a minimum 256-bit secret key.
        The value must be at least 64 hex characters (32 bytes = 256 bits).
        This check runs at STARTUP — invalid keys reject configuration.
        """
        if len(v) < 64:
            raise ValueError(
                "SECRET_KEY must be at least 64 hex characters (256 bits).\n"
                "  Generate one with:\n"
                "    python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        # Warn if the key looks like the placeholder from .env.example
        if "REPLACE_WITH" in v.upper():
            raise ValueError(
                "SECRET_KEY still contains the placeholder value from .env.example.\n"
                "  Replace it with a real random secret before starting."
            )
        return v

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: object) -> list[str]:
        """Accept comma-separated string, JSON list, or list."""
        if isinstance(v, str):
            v_trimmed = v.strip()
            if v_trimmed.startswith("[") and v_trimmed.endswith("]"):
                try:
                    import json
                    parsed = json.loads(v_trimmed)
                    if isinstance(parsed, list):
                        return [str(origin).strip() for origin in parsed if str(origin).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in v_trimmed.split(",") if origin.strip()]
        if isinstance(v, (list, tuple)):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return ["http://localhost:3000", "https://localhost"]

    @model_validator(mode="after")
    def validate_risk_thresholds(self) -> "Settings":
        """Risk thresholds must be strictly ordered."""
        assert self.risk_threshold_medium < self.risk_threshold_high, (
            "RISK_THRESHOLD_MEDIUM must be less than RISK_THRESHOLD_HIGH"
        )
        assert self.risk_threshold_high < self.risk_threshold_critical, (
            "RISK_THRESHOLD_HIGH must be less than RISK_THRESHOLD_CRITICAL"
        )
        return self

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_test(self) -> bool:
        return self.app_env == "test"

    @property
    def access_token_expire_seconds(self) -> int:
        return self.access_token_expire_minutes * 60

    @property
    def refresh_token_expire_seconds(self) -> int:
        return self.refresh_token_expire_days * 24 * 60 * 60


def _abort(message: str) -> None:
    """Print a fatal configuration error and exit."""
    border = "=" * 70
    print(f"\n{border}", file=sys.stderr)
    print("  SENTINELGATE STARTUP FAILURE — Configuration Error", file=sys.stderr)
    print(border, file=sys.stderr)
    print(f"\n  {message}", file=sys.stderr)
    print(f"{border}\n", file=sys.stderr)
    sys.exit(1)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached Settings singleton.
    Call this everywhere instead of instantiating Settings() directly.

    Usage:
        from backend.config import get_settings
        settings = get_settings()
    """
    return Settings()  # type: ignore[call-arg]
