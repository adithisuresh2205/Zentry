"""
SentinelGate Attack Simulations — Master Orchestrator
=====================================================
Executes the full suite of live attack simulations and legitimate traffic tests
against the Zero-Trust Security Gateway.

Simulations executed:
1. SQL Injection (A03:2021)
2. Cross-Site Scripting (XSS) (A03:2021)
3. Path Traversal & File Disclosure (A01:2021)
4. OS Command Injection (A03:2021)
5. Server-Side Request Forgery (SSRF) (A10:2021)
6. Credential Brute-Force Detection (A07:2021)
7. Sliding-Window Rate Limiting & Anti-Abuse (A04:2021)
8. Legitimate Production Traffic Baseline

Usage:
    python -m backend.tests.attack_simulations.run_all_simulations
"""
from __future__ import annotations

import os
import sys
import time

# Ensure Windows terminal handles UTF-8 cleanly
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backend.tests.attack_simulations.common import (
    DEFAULT_TARGET_URL,
    GREEN,
    RED,
    CYAN,
    YELLOW,
    BOLD,
    DIM,
    RESET,
)
from backend.tests.attack_simulations import (
    simulate_sqli,
    simulate_xss,
    simulate_path_traversal,
    simulate_cmd_injection,
    simulate_ssrf,
    simulate_brute_force,
    simulate_rate_limit,
    simulate_legitimate_traffic,
)

SIMULATIONS = [
    ("SQL Injection Defense", simulate_sqli.run),
    ("XSS Defense", simulate_xss.run),
    ("Path Traversal Defense", simulate_path_traversal.run),
    ("Command Injection Defense", simulate_cmd_injection.run),
    ("SSRF Defense", simulate_ssrf.run),
    ("Credential Brute-Force Mitigation", simulate_brute_force.run),
    ("Sliding-Window Rate Limiting", simulate_rate_limit.run),
    ("Legitimate Traffic Verification", simulate_legitimate_traffic.run),
]


def main() -> int:
    target_url = os.getenv("SENTINELGATE_URL", DEFAULT_TARGET_URL)
    width = 76

    print(f"\n{BOLD}{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  SENTINELGATE / ZENTRY - LIVE SECURITY ATTACK SIMULATION SUITE{RESET}")
    print(f"{DIM}  Target Gateway: {target_url} | Total Scenarios: {len(SIMULATIONS)}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}\n")

    results: list[tuple[str, bool, float]] = []
    overall_start = time.perf_counter()

    for name, runner in SIMULATIONS:
        start = time.perf_counter()
        try:
            passed = runner(target_url)
        except Exception as e:
            print(f"\n{RED}[!] Simulation '{name}' crashed with error: {e}{RESET}\n")
            passed = False
        duration = time.perf_counter() - start
        results.append((name, passed, duration))
        time.sleep(0.2)

    total_duration = time.perf_counter() - overall_start

    # Executive Summary Report
    print(f"\n\n{BOLD}{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  EXECUTIVE SECURITY VERIFICATION REPORT{RESET}")
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}\n")

    all_passed = True
    print(f"  {'Scenario':<42} {'Status':<16} {'Duration':<10}")
    print(f"  {'-' * 42} {'-' * 16} {'-' * 10}")

    for name, passed, duration in results:
        badge = f"{GREEN}PASS (100%){RESET}" if passed else f"{RED}FAIL{RESET}"
        dur_str = f"{duration:.2f}s"
        if not passed:
            all_passed = False
        print(f"  {name:<42} {badge:<25} {dur_str:<10}")

    print(f"\n  {BOLD}Total Execution Time:{RESET} {total_duration:.2f}s")
    print(f"  {BOLD}Zero-Trust Gateway Status:{RESET} " + (
        f"{GREEN}{BOLD}ALL DEFENSE TIERS OPERATIONAL & VERIFIED{RESET}"
        if all_passed else
        f"{RED}{BOLD}ATTACK SIMULATION ISSUES DETECTED{RESET}"
    ))
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
