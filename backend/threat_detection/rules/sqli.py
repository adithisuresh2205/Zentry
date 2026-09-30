"""
SentinelGate — SQL Injection Detection Rule
===========================================
OWASP A03:2021 — Injection
Detects SQL injection signatures across normalized paths, query params, headers, and bodies.
Severity: HIGH (+60 risk), Blocks directly (HTTP 403).
"""
from __future__ import annotations

import re

from backend.threat_detection.rules.base import RegexRule


class SQLInjectionRule(RegexRule):
    rule_id = "SQLI_001"
    name = "SQL Injection"
    category = "SQL_INJECTION"
    severity = "HIGH"
    risk_delta = 60
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
        # Boolean-based OR/AND tautologies: OR 1=1, AND 1=1
        re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
        # String tautologies: ' OR '1'='1', ' AND 'a'='a'
        re.compile(r"'\s*(or|and)\s+'[^']*'\s*=\s*'[^']*'", re.IGNORECASE),
        re.compile(r"'\s*(or|and)\s+'[^']*'", re.IGNORECASE),
        # UNION SELECT queries
        re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
        # SQL comment terminators when preceded by quotes or after statements
        re.compile(r"('\s*--|'\s*#|/\*.*?\*/|;\s*--)", re.IGNORECASE),
        # Stacked / destructive DDL/DML
        re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
        re.compile(r"\binsert\s+into\b", re.IGNORECASE),
        re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
        # SELECT ... FROM statements
        re.compile(r"\bselect\b[\s\S]{1,100}\bfrom\b", re.IGNORECASE),
        # Time-based blind SQLi: SLEEP(x), BENCHMARK(...)
        re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
        re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
    ]
