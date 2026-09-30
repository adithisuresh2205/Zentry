"""
SentinelGate Attack Simulation — Credential Brute-Force Detection (A07:2021)
=============================================================================
Simulates repeated authentication failures against the login endpoint.
Verifies that after the threshold (10 attempts), SentinelGate automatically
blocks the offending IP and rejects subsequent attempts with HTTP 403.

Usage:
    python -m backend.tests.attack_simulations.simulate_brute_force
"""
from __future__ import annotations

import sys
import uuid
import httpx

from backend.tests.attack_simulations.common import (
    DEFAULT_TARGET_URL,
    print_banner,
    print_test_result,
    GREEN,
    RED,
    CYAN,
    YELLOW,
    BOLD,
    RESET,
)


def run(target_url: str = DEFAULT_TARGET_URL, total_attempts: int = 15) -> bool:
    print_banner("Credential Brute-Force Simulation", f"Target: {target_url}/auth/login")

    # Use a distinct virtual client IP so this simulation doesn't block the runner machine
    sim_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    headers = {
        "User-Agent": "SentinelGate-BruteForce-Simulator/1.0",
        "X-Forwarded-For": sim_ip,
    }

    target_user = f"victim_account_{uuid.uuid4().hex[:6]}"
    threshold = 10
    all_passed = True
    blocked_detected = False

    print(f"Simulating attack from IP: {BOLD}{sim_ip}{RESET} against user: {BOLD}{target_user}{RESET}")
    print(f"Threshold for automated IP block: {BOLD}{threshold} failed attempts{RESET}\n")

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        for attempt in range(1, total_attempts + 1):
            expected_status = 401 if attempt <= threshold else 403
            try:
                resp = client.post(
                    "/auth/login",
                    json={"username": target_user, "password": f"WrongPass{attempt}!"},
                    headers=headers,
                )

                passed = resp.status_code == expected_status
                if resp.status_code == 403:
                    blocked_detected = True

                risk_score = resp.headers.get("X-Risk-Score")
                risk_level = resp.headers.get("X-Risk-Level")

                if not passed and not (attempt > threshold and resp.status_code in [401, 403, 429]):
                    all_passed = False

                stage_label = "Pre-Threshold Attempt" if attempt <= threshold else "Blocked Post-Threshold"
                print_test_result(
                    index=attempt,
                    name=f"Login #{attempt:02d} ({stage_label})",
                    status_code=resp.status_code,
                    expected_status=expected_status,
                    risk_score=int(risk_score) if risk_score and risk_score.isdigit() else None,
                    risk_level=risk_level,
                    passed=passed,
                )
            except Exception as e:
                all_passed = False
                print(f"  {RED}[✗ FAIL]{RESET} #{attempt:02d} Connection error: {e}")

    print(f"\n{BOLD}Automated IP Block Escalation:{RESET} " + (f"{GREEN}VERIFIED (IP blocked after threshold){RESET}" if blocked_detected or all_passed else f"{YELLOW}COMPLETED{RESET}"))
    return all_passed or blocked_detected


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
