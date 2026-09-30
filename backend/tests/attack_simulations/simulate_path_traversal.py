"""
SentinelGate Attack Simulation — Path Traversal (A01:2021)
==========================================================
Demonstrates detection and blocking of directory traversal attacks,
evasion techniques (double encoding), and sensitive system path probes.

Usage:
    python -m backend.tests.attack_simulations.simulate_path_traversal
"""
from __future__ import annotations

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

CLEAN_PATHS = [
    "product_specs.pdf",
    "report_q3_2026.xlsx",
    "avatar_user_12.png",
    "manual_v2.0.txt",
]

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "/proc/self/environ",
    r"..\..\windows\system32\config\sam",
    "../../../../var/log/auth.log",
    "../.env",
    "../../.git/config",
]


def run(target_url: str = DEFAULT_TARGET_URL) -> bool:
    print_banner("Path Traversal Attack Simulation", f"Target: {target_url}/api/search")
    token = get_auth_token(target_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "SentinelGate-Simulation-Agent/1.0",
    }

    all_passed = True
    test_idx = 1

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        # Phase 1: Legitimate filenames (Expect ALLOW -> HTTP 200)
        print(f"{BOLD}{CYAN}[+] Stage 1: Legitimate File References (Expected: 200 ALLOW){RESET}")
        for file_ref in CLEAN_PATHS:
            try:
                resp = client.get("/api/search", params={"q": file_ref}, headers=headers)
                passed = resp.status_code == 200
                risk_score = resp.headers.get("X-Risk-Score", "0")
                risk_level = resp.headers.get("X-Risk-Level", "LOW")
                if not passed:
                    all_passed = False
                print_test_result(
                    index=test_idx,
                    name=f"Clean: '{file_ref[:24]}'",
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

        # Phase 2: Malicious Path Traversal Payloads (Expect BLOCK -> HTTP 403)
        print(f"{BOLD}{CYAN}[+] Stage 2: Path Traversal Attack Payloads (Expected: 403 BLOCK){RESET}")
        for payload in TRAVERSAL_PAYLOADS:
            try:
                resp = client.get("/api/search", params={"file": payload}, headers=headers)
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
                    name=f"Traversal: '{payload[:24]}'",
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

    print(f"\n{BOLD}Result:{RESET} " + (f"{GREEN}ALL PATH TRAVERSAL TESTS PASSED [100% Intercepted]{RESET}" if all_passed else f"{RED}SOME PATH TRAVERSAL TESTS FAILED{RESET}"))
    return all_passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
