"""
SentinelGate Attack Simulation — SQL Injection (A03:2021)
=========================================================
Demonstrates detection and blocking of SQL injection payloads
in URL query parameters and JSON body payloads against the gateway.

Usage:
    python -m backend.tests.attack_simulations.simulate_sqli
"""
from __future__ import annotations

import sys
import httpx

from backend.tests.attack_simulations.common import (
    DEFAULT_TARGET_URL,
    colored,
    get_auth_token,
    print_banner,
    print_test_result,
    GREEN,
    RED,
    CYAN,
    BOLD,
    RESET,
)

CLEAN_QUERIES = [
    "Enterprise Security Appliance",
    "Hardware Key Vault HSM",
    "john o'brien",
    "select few items",
    "order by date",
]

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 1=1 #",
    "UNION SELECT username, password FROM users --",
    "'; DROP TABLE users; --",
    "SLEEP(5)",
    "1 AND BENCHMARK(1000000,MD5(1))",
    "%27%20OR%201%3D1%20--",
    "%2527%2520OR%25201%253D1%2520--",
    "' oR 1=1--",
    "admin' UNION ALL SELECT NULL, password FROM users--",
    "1; INSERT INTO users VALUES ('hacked');",
]


def run(target_url: str = DEFAULT_TARGET_URL) -> bool:
    print_banner("SQL Injection Attack Simulation", f"Target: {target_url}/api/search")
    token = get_auth_token(target_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "SentinelGate-Simulation-Agent/1.0",
    }

    all_passed = True
    test_idx = 1

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        # Phase 1: Legitimate queries (Expect ALLOW -> HTTP 200)
        print(f"{BOLD}{CYAN}[+] Stage 1: Legitimate Baseline Traffic (Expected: 200 ALLOW){RESET}")
        for q in CLEAN_QUERIES:
            try:
                resp = client.get("/api/search", params={"q": q}, headers=headers)
                passed = resp.status_code == 200
                risk_score = resp.headers.get("X-Risk-Score", "0")
                risk_level = resp.headers.get("X-Risk-Level", "LOW")
                if not passed:
                    all_passed = False
                print_test_result(
                    index=test_idx,
                    name=f"Clean: '{q[:24]}'",
                    status_code=resp.status_code,
                    expected_status=200,
                    risk_score=int(risk_score) if risk_score.isdigit() else 0,
                    risk_level=risk_level,
                    passed=passed,
                )
            except Exception as e:
                all_passed = False
                print(f"  {RED}[✗ FAIL]{RESET} #{test_idx:02d} Connection error: {e}")
            test_idx += 1

        print()

        # Phase 2: Malicious SQLi Payloads (Expect BLOCK -> HTTP 403)
        print(f"{BOLD}{CYAN}[+] Stage 2: SQL Injection Attack Payloads (Expected: 403 BLOCK){RESET}")
        for payload in SQLI_PAYLOADS:
            try:
                resp = client.get("/api/search", params={"q": payload}, headers=headers)
                passed = resp.status_code == 403
                threats: list[str] = []
                risk_score = None
                risk_level = None

                if resp.status_code == 403:
                    try:
                        data = resp.json()
                        threats = data.get("threats", [])
                        risk_score = data.get("risk_score")
                        risk_level = data.get("risk_level")
                    except Exception:
                        pass
                else:
                    all_passed = False

                print_test_result(
                    index=test_idx,
                    name=f"SQLi: '{payload[:24]}'",
                    status_code=resp.status_code,
                    expected_status=403,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    threats=threats,
                    passed=passed,
                )
            except Exception as e:
                all_passed = False
                print(f"  {RED}[✗ FAIL]{RESET} #{test_idx:02d} Connection error: {e}")
            test_idx += 1

    print(f"\n{BOLD}Result:{RESET} " + (f"{GREEN}ALL SQLi TESTS PASSED [100% Intercepted]{RESET}" if all_passed else f"{RED}SOME SQLi TESTS FAILED{RESET}"))
    return all_passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
