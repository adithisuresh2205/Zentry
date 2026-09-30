"""
SentinelGate Attack Simulations — Shared Test Harness & Utilities
===================================================================
Provides shared HTTP clients, payload generators, colored terminal output,
and assertion helpers for all attack simulation scenarios.
"""
from __future__ import annotations

import os
import sys
from datetime import timedelta
from typing import Any

import httpx

# Ensure Windows terminal handles UTF-8 cleanly
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Default target gateway endpoint
DEFAULT_TARGET_URL = os.getenv("SENTINELGATE_URL", "http://127.0.0.1:8000")

# ANSI terminal formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def colored(text: str, color_code: str) -> str:
    return f"{color_code}{text}{RESET}"


def print_banner(title: str, subtitle: str = "") -> None:
    width = 76
    print(f"\n{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  [*] {title.upper()}{RESET}")
    if subtitle:
        print(f"{DIM}      {subtitle}{RESET}")
    print(f"{CYAN}{'=' * width}{RESET}\n")


def print_test_result(
    index: int,
    name: str,
    status_code: int,
    expected_status: int,
    risk_score: int | None = None,
    risk_level: str | None = None,
    threats: list[str] | None = None,
    passed: bool = True,
    reason: str = "",
) -> None:
    badge = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    status_str = f"HTTP {status_code} (expected {expected_status})"
    risk_str = f"Risk: {risk_score} ({risk_level})" if risk_score is not None else ""
    threats_str = f"Threats: {', '.join(threats)}" if threats else ""

    extra = " | ".join(filter(None, [risk_str, threats_str, reason]))
    extra_disp = f" - {DIM}{extra}{RESET}" if extra else ""

    print(f"  {badge} #{index:02d} {BOLD}{name:<32}{RESET} [{status_str}]{extra_disp}")


def get_auth_token(base_url: str = DEFAULT_TARGET_URL) -> str:
    """
    Obtain or mint a valid access token for simulation scenarios.
    Attempts live authentication first so user exists in database for require_user check.
    """
    try:
        with httpx.Client(base_url=base_url, timeout=5.0) as client:
            resp = client.post(
                "/auth/login",
                json={"username": "admin", "password": "admin123"},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token", "")
            elif resp.status_code in (401, 404):
                client.post(
                    "/auth/register",
                    json={"username": "sim_analyst", "password": "SimPassword123!", "role": "ANALYST"},
                )
                resp2 = client.post(
                    "/auth/login",
                    json={"username": "sim_analyst", "password": "SimPassword123!"},
                )
                if resp2.status_code == 200:
                    return resp2.json().get("access_token", "")
    except Exception:
        pass

    try:
        from backend.auth.service import create_jwt_token
        token, _ = create_jwt_token(
            user_id="sim-user-001",
            username="sim_analyst",
            role="ANALYST",
            token_type="access",
            expires_delta=timedelta(hours=2),
        )
        return token
    except Exception:
        import jwt
        secret = os.getenv("SECRET_KEY", "a" * 64)
        return jwt.encode(
            {"sub": "sim-user-001", "username": "sim_analyst", "role": "ANALYST", "type": "access"},
            secret,
            algorithm="HS256",
        )
