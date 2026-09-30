"""
SentinelGate — Cross-Site Scripting (XSS) Detection Rule
========================================================
OWASP A03:2021 — Injection
Detects reflected, stored, and DOM XSS attack signatures.
Severity: HIGH (+55 risk), Blocks directly (HTTP 403).
"""
from __future__ import annotations

import re

from backend.threat_detection.rules.base import RegexRule


class XSSRule(RegexRule):
    rule_id = "XSS_001"
    name = "Cross-Site Scripting (XSS)"
    category = "XSS"
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
        # Explicit <script> tag opening or closing
        re.compile(r"<\s*script[\s>]", re.IGNORECASE),
        re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
        # javascript: pseudo-protocol in URLs / attributes
        re.compile(r"javascript\s*:\s*", re.IGNORECASE),
        # HTML event handlers: onerror=, onload=, onclick=, onmouseover=
        re.compile(r"\bon[a-z]{3,15}\s*=\s*[\"']?[^\"'>]*", re.IGNORECASE),
        # Sensitive DOM properties: document.cookie, document.location, window.location
        re.compile(r"\bdocument\s*\.\s*cookie\b", re.IGNORECASE),
        re.compile(r"\b(document|window)\s*\.\s*location\b", re.IGNORECASE),
        # Dynamic execution sinks: eval(...), setTimeout('...'), setInterval('...')
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        # Obfuscation primitives: String.fromCharCode
        re.compile(r"\bstring\s*\.\s*fromcharcode\b", re.IGNORECASE),
        # Embedded HTML vector tags: <iframe>, <object>, <embed>, <svg ... onload
        re.compile(r"<\s*(iframe|object|embed)\b", re.IGNORECASE),
        re.compile(r"<\s*svg\b[^>]*\bon[a-z]+\s*=", re.IGNORECASE),
        re.compile(r"<\s*img\b[^>]*\b(onerror|onload|src\s*=\s*[\"']?javascript)", re.IGNORECASE),
    ]
