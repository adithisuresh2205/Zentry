"""
SentinelGate — Suspicious User-Agent Detection Rule
===================================================
Detects known automated vulnerability scanner signatures, headless crawlers,
missing or excessively long User-Agents.
Severity: LOW to HIGH (+10 to +25 risk).
Does NOT block by itself (blocks_directly=False); contributes to risk scoring.
"""
from __future__ import annotations

import re

from backend.schemas.context import GatewayContext, ThreatMatch
from backend.threat_detection.normalizer import InspectionTarget
from backend.threat_detection.rules.base import DetectionRule

# Signatures of automated attack scanners and penetration testing tools
SCANNER_PATTERN = re.compile(
    r"\b(sqlmap|nikto|nmap|dirbuster|burpsuite|nessus|masscan|acunetix|havij|zaproxy|w3af|gobuster|ffuf|nuclei)\b",
    re.IGNORECASE,
)

CLI_CLIENT_PATTERN = re.compile(r"^(curl|wget|python-requests|aiohttp|httpie)\b", re.IGNORECASE)


class UserAgentRule(DetectionRule):
    rule_id = "USER_AGENT_001"
    name = "Suspicious User-Agent"
    category = "SUSPICIOUS_UA"
    severity = "MEDIUM"
    risk_delta = 10
    blocks_directly = False
    status_code = 403

    def inspect(
        self,
        ctx: GatewayContext,
        targets: list[InspectionTarget],
    ) -> list[ThreatMatch]:
        if not self.enabled:
            return []

        ua = ctx.headers.get("user-agent")

        # 1. Missing or empty User-Agent header
        if ua is None or not ua.strip():
            return [
                ThreatMatch(
                    rule_id="UA_MISSING",
                    category="SUSPICIOUS_UA",
                    severity="LOW",
                    risk_delta=15,
                    details="Request is missing or has an empty User-Agent header",
                    target="header:user-agent",
                )
            ]

        # 2. Known automated security scanner signatures
        m_scanner = SCANNER_PATTERN.search(ua)
        if m_scanner:
            matched_tool = m_scanner.group(0)
            return [
                ThreatMatch(
                    rule_id="UA_SCANNER",
                    category="SUSPICIOUS_UA",
                    severity="HIGH",
                    risk_delta=25,
                    details=f"Known vulnerability scanner signature detected: '{matched_tool}'",
                    target="header:user-agent",
                )
            ]

        # 3. Excessively long User-Agent header (> 500 characters, potential buffer overflow probe)
        if len(ua) > 500:
            return [
                ThreatMatch(
                    rule_id="UA_OVERFLOW",
                    category="SUSPICIOUS_UA",
                    severity="LOW",
                    risk_delta=10,
                    details=f"User-Agent length exceeds 500 characters ({len(ua)} chars)",
                    target="header:user-agent",
                )
            ]

        # 4. CLI tool with no browser identity (curl, wget, etc.)
        m_cli = CLI_CLIENT_PATTERN.search(ua)
        if m_cli:
            return [
                ThreatMatch(
                    rule_id="UA_CLI_CLIENT",
                    category="SUSPICIOUS_UA",
                    severity="LOW",
                    risk_delta=10,
                    details=f"CLI client without browser identity: '{m_cli.group(0)}'",
                    target="header:user-agent",
                )
            ]

        return []
