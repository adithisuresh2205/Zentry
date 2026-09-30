"""
SentinelGate Attack Simulation — Server-Side Request Forgery (SSRF) (A10:2021)
==============================================================================
Demonstrates detection and blocking of SSRF targeting cloud metadata services
(AWS/GCP), internal RFC1918 subnets, loopback adapters, and dangerous URI schemes.

Usage:
    python -m backend.tests.attack_simulations.simulate_ssrf
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

CLEAN_URLS = [
    "https://api.github.com/events",
    "https://hooks.slack.com/services/T00000000/B00000000/XXXXX",
    "https://example.com/webhook",
    "http://public-site.org/index.html",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8080/admin",
    "http://localhost:3000/internal",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_flushall",
    "dict://127.0.0.1:11211/stat",
    "http://192.168.1.1/router",
    "http://10.0.0.5/secrets",
    "https://instance-data/latest/meta-data",
]


def run(target_url: str = DEFAULT_TARGET_URL) -> bool:
    print_banner("SSRF Attack Simulation", f"Target: {target_url}/api/search")
    token = get_auth_token(target_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "SentinelGate-Simulation-Agent/1.0",
    }

    all_passed = True
    test_idx = 1

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        # Phase 1: Legitimate external URLs (Expect ALLOW -> HTTP 200)
        print(f"{BOLD}{CYAN}[+] Stage 1: Legitimate External Endpoints (Expected: 200 ALLOW){RESET}")
        for clean_url in CLEAN_URLS:
            try:
                resp = client.get("/api/search", params={"q": "webhook", "url": clean_url}, headers=headers)
                passed = resp.status_code == 200
                risk_score = resp.headers.get("X-Risk-Score", "0")
                risk_level = resp.headers.get("X-Risk-Level", "LOW")
                if not passed:
                    all_passed = False
                print_test_result(
                    index=test_idx,
                    name=f"Clean URL: '{clean_url[:24]}'",
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

        # Phase 2: Malicious SSRF Payloads (Expect BLOCK -> HTTP 403)
        print(f"{BOLD}{CYAN}[+] Stage 2: SSRF Internal Probes (Expected: 403 BLOCK){RESET}")
        for payload in SSRF_PAYLOADS:
            try:
                resp = client.get("/api/search", params={"q": "probe", "url": payload}, headers=headers)
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
                    name=f"SSRF: '{payload[:24]}'",
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

    print(f"\n{BOLD}Result:{RESET} " + (f"{GREEN}ALL SSRF TESTS PASSED [100% Intercepted]{RESET}" if all_passed else f"{RED}SOME SSRF TESTS FAILED{RESET}"))
    return all_passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
