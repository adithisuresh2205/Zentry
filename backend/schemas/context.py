"""
SentinelGate — Gateway Context & Pipeline Schemas
==================================================
Defines data structures representing the evaluated request context,
pipeline results, security check signatures, and user representations.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class UserContext(BaseModel):
    """Authenticated user context attached to request."""
    user_id: str
    username: str
    role: Literal["ADMIN", "ANALYST", "USER"]


class ThreatMatch(BaseModel):
    """Details of a matched threat detection rule."""
    rule_id: str
    category: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_delta: int = Field(ge=0, le=100)
    details: str | None = None
    target: str | None = None  # e.g., "query:q", "body:username", "header:user-agent"


class CheckResult(BaseModel):
    """Result of an individual security check in the pipeline."""
    passed: bool
    risk_delta: int = 0
    threat: ThreatMatch | None = None
    block_reason: str | None = None
    status_code: int = 403


class GatewayContext(BaseModel):
    """
    Mutable state object passed through every stage of the gateway pipeline.
    Accumulates risk score, matched threats, authentication status,
    and the final policy decision.
    """
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    client_ip: str
    is_ipv6: bool = False
    method: str
    path: str
    query_string: str = ""
    user_agent: str = ""
    query_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes | None = None
    authenticated_user: UserContext | None = None
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    threats: list[ThreatMatch] = Field(default_factory=list)
    decision: Literal["ALLOW", "BLOCK", "LOG"] = "ALLOW"
    response_status: int | None = None
    blocked_reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def add_risk(self, delta: int) -> None:
        """Add to risk score with strict ceiling at 100."""
        self.risk_score = min(100, max(0, self.risk_score + delta))
        self._update_risk_level()

    def _update_risk_level(self) -> None:
        if self.risk_score >= 80:
            self.risk_level = "CRITICAL"
        elif self.risk_score >= 60:
            self.risk_level = "HIGH"
        elif self.risk_score >= 30:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"
