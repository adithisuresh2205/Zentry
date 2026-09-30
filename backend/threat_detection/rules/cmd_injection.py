"""
SentinelGate — Command Injection Detection Rule
===============================================
OWASP A03:2021 — Injection
Detects operating system command chaining, backtick execution, and subshells.
Severity: CRITICAL (+70 risk), Blocks directly (HTTP 403).
"""
from __future__ import annotations

import re

from backend.threat_detection.rules.base import RegexRule


class CommandInjectionRule(RegexRule):
    rule_id = "CMD_INJECTION_001"
    name = "Command Injection"
    category = "COMMAND_INJECTION"
    severity = "CRITICAL"
    risk_delta = 70
    blocks_directly = True
    status_code = 403

    ignored_locations = {
        "header:host",
        "header:accept",
        "header:accept-encoding",
        "header:accept-language",
        "header:connection",
        "header:content-type",
        "header:content-length",
    }

    compiled_patterns = [
        # Command chaining operators followed by sensitive utilities
        re.compile(
            r"[;&|]\s*(whoami|id|uname|cat|rm|wget|curl|bash|sh|zsh|python|perl|ruby|powershell|cmd)\b",
            re.IGNORECASE,
        ),
        # Backtick command substitution: `whoami`
        re.compile(r"`[^`\n]{1,100}`", re.IGNORECASE),
        # Subshell execution: $(whoami)
        re.compile(r"\$\(\s*(whoami|id|cat|ls|uname|curl|wget)[^)]*\)", re.IGNORECASE),
        # Netcat / reverse shell listener invocation: nc -lvnp 4444, ncat 1.2.3.4 80
        re.compile(r"\b(nc|netcat|ncat)\b[\s\S]{1,50}\d{1,5}", re.IGNORECASE),
        # Redirection to dev null or shell pipelines
        re.compile(r"/dev/(tcp|udp)/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
    ]
