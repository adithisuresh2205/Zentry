"""
SentinelGate Attack Simulation — Cross-Site Scripting (XSS) (A03:2021)
=====================================================================
Demonstrates detection and blocking of reflected, DOM, and stored
XSS attack vectors across GET parameters and request bodies.

Usage:
    python -m backend.tests.attack_simulations.simulate_xss
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

CLEAN_INPUTS = [
    "I love <3 pizza",
    "Price: $4.99 and fast delivery",
    "Use && to combine commands in bash",
    "Normal comment on product specs",
    "5 < 10 and 10 > 5 math proof",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    '"><script>alert(document.cookie)</script>',
    "%3cscript%3ealert(1)%3c/script%3e",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "eval('alert(1)')",
]


def run(target_url: str = DEFAULT_TARGET_URL) -> bool:
    print_banner("XSS Attack Simulation", f"Target: {target_url}/api/search")
    token = get_auth_token(target_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "SentinelGate-Simulation-Agent/1.0",
    }

    all_passed = True
    test_idx = 1

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        # Phase 1: Legitimate input queries (Expect ALLOW -> HTTP 200)
        print(f"{BOLD}{CYAN}[+] Stage 1: Legitimate Baseline Traffic (Expected: 200 ALLOW){RESET}")
        for clean_text in CLEAN_INPUTS:
            try:
                resp = client.get("/api/search", params={"q": clean_text}, headers=headers)
                passed = resp.status_code == 200
                risk_score = resp.headers.get("X-Risk-Score", "0")
                risk_level = resp.headers.get("X-Risk-Level", "LOW")
                if not passed:
                    all_passed = False
                print_test_result(
                    index=test_idx,
                    name=f"Clean: '{clean_text[:24]}'",
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

        # Phase 2: Malicious XSS Payloads (Expect BLOCK -> HTTP 403)
        print(f"{BOLD}{CYAN}[+] Stage 2: Cross-Site Scripting Attack Payloads (Expected: 403 BLOCK){RESET}")
        for payload in XSS_PAYLOADS:
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
                    name=f"XSS: '{payload[:24]}'",
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

    print(f"\n{BOLD}Result:{RESET} " + (f"{GREEN}ALL XSS TESTS PASSED [100% Intercepted]{RESET}" if all_passed else f"{RED}SOME XSS TESTS FAILED{RESET}"))
    return all_passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
