"""
SentinelGate Traffic Simulation — Legitimate Traffic Baseline
=============================================================
Simulates a realistic production workload distribution:
- 80% clean GET requests to mock resource APIs (/api/products, /api/users)
- 10% authentication / session operations (/api/login)
- 10% search queries with legitimate terms (/api/search?q=...)

Verifies that all benign requests are ALLOWED (HTTP 200) with low risk scores (< 30).

Usage:
    python -m backend.tests.attack_simulations.simulate_legitimate_traffic
"""
from __future__ import annotations

import random
import sys
import httpx

from backend.tests.attack_simulations.common import (
    DEFAULT_TARGET_URL,
    get_auth_token,
    print_banner,
    print_test_result,
    GREEN,
    RED,
    CYAN,
    BOLD,
    RESET,
)

SEARCH_TERMS = [
    "Firewall Appliance",
    "Security Vault",
    "Hardware Security Module",
    "Elena Rostova",
    "Marcus Vance",
    "Network Bridge",
    "SSL Certificate",
    "Backup Power Unit",
]


def run(target_url: str = DEFAULT_TARGET_URL, total_requests: int = 40) -> bool:
    print_banner("Legitimate Traffic Simulation", f"Target: {target_url} — {total_requests} requests")
    token = get_auth_token(target_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }

    all_passed = True
    allowed_count = 0
    high_risk_count = 0

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        for idx in range(1, total_requests + 1):
            roll = random.random()

            try:
                if roll < 0.80:
                    # 80% GET resource endpoints
                    endpoint = "/api/products" if random.random() < 0.5 else "/api/users"
                    resp = client.get(endpoint, headers=headers)
                    req_type = f"GET {endpoint}"
                elif roll < 0.90:
                    # 10% Auth operations
                    resp = client.post(
                        "/api/login",
                        json={"username": "demo_user", "password": "SamplePassword123!"},
                        headers=headers,
                    )
                    req_type = "POST /api/login"
                else:
                    # 10% Search requests
                    term = random.choice(SEARCH_TERMS)
                    resp = client.get("/api/search", params={"q": term}, headers=headers)
                    req_type = f"GET /api/search?q={term[:12]}"

                passed = resp.status_code == 200
                risk_str = resp.headers.get("X-Risk-Score", "0")
                risk = int(risk_str) if risk_str.isdigit() else 0
                risk_level = resp.headers.get("X-Risk-Level", "LOW")

                if passed and risk < 30:
                    allowed_count += 1
                else:
                    all_passed = False
                    if risk >= 30:
                        high_risk_count += 1

                if idx <= 5 or idx % 10 == 0 or not passed:
                    print_test_result(
                        index=idx,
                        name=req_type[:32],
                        status_code=resp.status_code,
                        expected_status=200,
                        risk_score=risk,
                        risk_level=risk_level,
                        passed=passed and risk < 30,
                    )
            except Exception as e:
                all_passed = False
                print(f"  {RED}[✗ FAIL]{RESET} #{idx:02d} Connection error: {e}")

    print(f"\n{BOLD}Legitimate Traffic Summary:{RESET}")
    print(f"  Total Requests:  {total_requests}")
    print(f"  Passed (ALLOW):  {allowed_count} / {total_requests}")
    print(f"  High Risk (>30): {high_risk_count}")

    success = all_passed and (allowed_count == total_requests)
    print(f"\n{BOLD}Verdict:{RESET} " + (f"{GREEN}ALL LEGITIMATE TRAFFIC ALLOWED WITH LOW RISK{RESET}" if success else f"{RED}SOME LEGITIMATE REQUESTS FLAGGED{RESET}"))
    return success


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
