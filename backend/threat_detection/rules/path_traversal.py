"""
SentinelGate — Path Traversal Detection Rule
============================================
OWASP A01:2021 — Broken Access Control
Detects directory traversal sequences and access to sensitive system files.
Severity: HIGH (+55 risk), Blocks directly (HTTP 403).
"""
from __future__ import annotations

import re

from backend.threat_detection.rules.base import RegexRule


class PathTraversalRule(RegexRule):
    rule_id = "PATH_TRAVERSAL_001"
    name = "Path Traversal"
    category = "PATH_TRAVERSAL"
    severity = "HIGH"
    risk_delta = 55
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
        # Classic directory traversal sequences: ../ or ..\
        re.compile(r"\.\.[\\/]", re.IGNORECASE),
        # Sensitive Unix system paths
        re.compile(r"/(etc|var|usr)/+(passwd|shadow|hosts|sudoers|crontab)", re.IGNORECASE),
        # Sensitive process / environment exploration
        re.compile(r"/proc/(self|\d+)/(environ|cmdline|status|maps)", re.IGNORECASE),
        # Sensitive Windows system files
        re.compile(r"(windows|winnt)[\\/]+system32[\\/]+(config[\\/]+sam|cmd\.exe)", re.IGNORECASE),
        re.compile(r"[\\/]boot\.ini\b", re.IGNORECASE),
        # Sensitive application dotfiles
        re.compile(r"\.(env|htaccess|htpasswd|git|bash_history|ssh)\b", re.IGNORECASE),
    ]
