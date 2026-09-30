"""
SentinelGate — Audit Package
============================
Export audit logger and cryptographic integrity verification utilities.
"""
from backend.audit.integrity import compute_event_hmac, verify_hmac_chain
from backend.audit.logger import AuditLogger, get_audit_logger, reset_audit_logger

__all__ = [
    "AuditLogger",
    "get_audit_logger",
    "reset_audit_logger",
    "compute_event_hmac",
    "verify_hmac_chain",
]
