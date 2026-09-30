"""
SentinelGate — Threat Detection Rules Package
=============================================
Exports all active WAF detection rules.
"""
from __future__ import annotations

from backend.threat_detection.rules.base import DetectionRule, RegexRule
from backend.threat_detection.rules.cmd_injection import CommandInjectionRule
from backend.threat_detection.rules.method_abuse import MethodAbuseRule
from backend.threat_detection.rules.path_traversal import PathTraversalRule
from backend.threat_detection.rules.sqli import SQLInjectionRule
from backend.threat_detection.rules.ssrf import SSRFRule
from backend.threat_detection.rules.user_agent import UserAgentRule
from backend.threat_detection.rules.xss import XSSRule


def get_default_rules() -> list[DetectionRule]:
    """Return an ordered list of default WAF inspection rules."""
    return [
        MethodAbuseRule(),
        SQLInjectionRule(),
        XSSRule(),
        PathTraversalRule(),
        CommandInjectionRule(),
        SSRFRule(),
        UserAgentRule(),
    ]


__all__ = [
    "CommandInjectionRule",
    "DetectionRule",
    "MethodAbuseRule",
    "PathTraversalRule",
    "RegexRule",
    "SQLInjectionRule",
    "SSRFRule",
    "UserAgentRule",
    "XSSRule",
    "get_default_rules",
]
