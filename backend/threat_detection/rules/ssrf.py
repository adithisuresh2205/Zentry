"""
SentinelGate — SSRF (Server-Side Request Forgery) Detection Rule
================================================================
OWASP A10:2021 — Server-Side Request Forgery (SSRF)
Detects access to internal RFC1918 addresses, cloud metadata services (AWS/GCP),
loopback interfaces, and dangerous protocol schemes (file://, gopher://).
Severity: HIGH (+65 risk), Blocks directly (HTTP 403).
"""
from __future__ import annotations

import re

from backend.threat_detection.rules.base import RegexRule


class SSRFRule(RegexRule):
    rule_id = "SSRF_001"
    name = "Server-Side Request Forgery (SSRF)"
    category = "SSRF"
    severity = "HIGH"
    risk_delta = 65
    blocks_directly = True
    status_code = 403

    ignored_locations = {
        "header:host",
        "header:origin",
        "header:referer",
        "header:accept",
        "header:accept-encoding",
        "header:accept-language",
        "header:connection",
        "header:content-type",
        "header:content-length",
    }

    compiled_patterns = [
        # Dangerous URI schemes
        re.compile(r"\b(file|gopher|dict|ldap|tftp)://", re.IGNORECASE),
        # Loopback interfaces in URLs or payloads
        re.compile(r"://(?:[^@/\n]+@)?(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0|\[?::1\]?)(?::\d+)?", re.IGNORECASE),
        # Cloud metadata endpoints (AWS, GCP, Azure)
        re.compile(r"169\.254\.169\.254", re.IGNORECASE),
        re.compile(r"metadata\.google\.internal", re.IGNORECASE),
        re.compile(r"instance-data", re.IGNORECASE),
        # Private RFC1918 subnets when embedded after protocol schemes
        re.compile(r"://(?:[^@/\n]+@)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d+)?", re.IGNORECASE),
    ]
