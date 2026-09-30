"""
SentinelGate — Audit Logger & Background Ingestion Worker
=========================================================
Non-blocking structured security audit logger.
Events are queued via an in-memory asyncio.Queue and ingested by a background worker.
Each event is chained cryptographically using HMAC-SHA256.
If the primary database is unavailable, events fall back to local structured JSON logging.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog
from sqlalchemy import select

from backend.audit.integrity import compute_event_hmac
from backend.config import get_settings
from backend.database.models import SecurityEvent
from backend.database.session import get_session_factory
from backend.schemas.context import GatewayContext

log = structlog.get_logger(__name__)


class AuditLogger:
    """
    Asynchronous, non-blocking audit event logger.
    """

    def __init__(self, queue_size: int = 10000, fallback_path: str = "audit_fallback.jsonl") -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self.fallback_path = fallback_path
        self._worker_task: asyncio.Task[None] | None = None
        self._last_hmac: str | None = None
        self._running = False

    def start(self) -> None:
        """Start the background worker if not already running."""
        if not self._running:
            self._running = True
            loop = asyncio.get_event_loop()
            self._worker_task = loop.create_task(self._worker_loop())
            log.info("audit.worker.started")

    async def stop(self) -> None:
        """Gracefully drain the queue and stop the background worker."""
        if not self._running:
            return

        self._running = False
        # Wait for currently queued items to be processed
        await self.flush()

        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        log.info("audit.worker.stopped")

    async def flush(self) -> None:
        """Wait until all queued events are fully processed."""
        if self.queue.qsize() > 0:
            try:
                await asyncio.wait_for(self.queue.join(), timeout=5.0)
            except asyncio.TimeoutError:
                log.warn("audit.flush.timeout")

    def log_event(
        self,
        ctx: GatewayContext,
        response_code: int = 200,
        duration_ms: int = 0,
    ) -> None:
        """
        Evaluate context and non-blockingly enqueue security event for persistence.

        Records:
        - All BLOCKED requests (status >= 400 or ctx.decision == 'BLOCK')
        - All ALLOWED requests with risk_score >= risk_threshold_medium (30)
        - All requests if audit_log_all is enabled
        """
        settings = get_settings()

        should_log = (
            ctx.decision == "BLOCK"
            or ctx.risk_score >= settings.risk_threshold_medium
            or response_code >= 400
            or getattr(settings, "audit_log_all", False)
        )

        if not should_log:
            log.debug(
                "audit.event.skipped",
                request_id=ctx.request_id,
                risk_score=ctx.risk_score,
                decision=ctx.decision,
            )
            return

        threat_list: list[dict[str, Any]] = []
        for t in ctx.threats:
            if hasattr(t, "to_dict"):
                threat_list.append(t.to_dict())
            elif isinstance(t, dict):
                threat_list.append(t)
            else:
                threat_list.append({
                    "rule_id": getattr(t, "rule_id", "UNKNOWN"),
                    "category": getattr(t, "category", "UNKNOWN"),
                    "severity": getattr(t, "severity", "UNKNOWN"),
                    "description": getattr(t, "description", ""),
                })

        user_id = ctx.authenticated_user.user_id if ctx.authenticated_user else None

        query_str = getattr(ctx, "query_string", "")
        if not query_str and ctx.query_params:
            from urllib.parse import urlencode  # noqa: PLC0415
            query_str = urlencode(ctx.query_params)

        ua_str = getattr(ctx, "user_agent", "") or ctx.headers.get("user-agent", "")

        event_dict: dict[str, Any] = {
            "id": str(uuid4()),
            "request_id": str(ctx.request_id),
            "timestamp": ctx.timestamp,
            "source_ip": ctx.client_ip,
            "client_ipv6": ctx.is_ipv6,
            "method": ctx.method,
            "path": ctx.path,
            "query_string": query_str or None,
            "user_agent": ua_str or None,
            "user_id": user_id,
            "threats": threat_list,
            "risk_score": ctx.risk_score,
            "risk_level": ctx.risk_level,
            "action": ctx.decision,
            "response_code": response_code,
            "duration_ms": duration_ms,
        }

        try:
            self.queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            log.error("audit.queue.full", request_id=ctx.request_id)
            self._write_fallback(event_dict)

    async def _worker_loop(self) -> None:
        """Background worker loop draining event queue."""
        while self._running or not self.queue.empty():
            try:
                try:
                    event_data = await asyncio.wait_for(self.queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

                try:
                    await self._process_event(event_data)
                finally:
                    self.queue.task_done()
            except asyncio.CancelledError:
                # Drain remaining items before dying
                while not self.queue.empty():
                    try:
                        event_data = self.queue.get_nowait()
                        try:
                            await self._process_event(event_data)
                        finally:
                            self.queue.task_done()
                    except (asyncio.QueueEmpty, asyncio.CancelledError):
                        break
                raise
            except Exception as exc:
                log.exception("audit.worker.unexpected_error", error=str(exc))

    async def _get_last_hmac(self) -> str:
        """Retrieve previous HMAC chain value from cache or database."""
        if self._last_hmac is not None:
            return self._last_hmac

        try:
            session_factory = get_session_factory()
            async with session_factory() as session:
                stmt = (
                    select(SecurityEvent.hmac_chain)
                    .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
                    .limit(1)
                )
                result = await session.execute(stmt)
                last_chain = result.scalar_one_or_none()
                self._last_hmac = last_chain or ""
        except Exception as exc:
            log.warn("audit.hmac.db_fetch_failed", error=str(exc))
            self._last_hmac = ""

        return self._last_hmac

    async def _process_event(self, event_data: dict[str, Any]) -> None:
        """Compute HMAC chain and persist event to database or fallback."""
        prev_hmac = await self._get_last_hmac()
        hmac_chain = compute_event_hmac(
            prev_hmac=prev_hmac,
            request_id=event_data["request_id"],
            timestamp=event_data["timestamp"],
            risk_score=event_data["risk_score"],
            action=event_data["action"],
        )
        event_data["hmac_chain"] = hmac_chain
        self._last_hmac = hmac_chain

        try:
            session_factory = get_session_factory()
            async with session_factory() as session:
                record = SecurityEvent(
                    id=event_data["id"],
                    request_id=event_data["request_id"],
                    timestamp=event_data["timestamp"],
                    source_ip=event_data["source_ip"],
                    client_ipv6=event_data["client_ipv6"],
                    method=event_data["method"],
                    path=event_data["path"],
                    query_string=event_data["query_string"],
                    user_agent=event_data["user_agent"],
                    user_id=event_data["user_id"],
                    threats=event_data["threats"],
                    risk_score=event_data["risk_score"],
                    risk_level=event_data["risk_level"],
                    action=event_data["action"],
                    response_code=event_data["response_code"],
                    duration_ms=event_data["duration_ms"],
                    hmac_chain=hmac_chain,
                )
                session.add(record)
                await session.commit()
                log.debug("audit.event.saved", request_id=event_data["request_id"], hmac=hmac_chain[:8])
        except Exception as exc:
            log.error("audit.db.insert_failed", error=str(exc), request_id=event_data["request_id"])
            self._write_fallback(event_data)

        # Phase 10: Broadcast to active WebSocket live feed subscribers
        try:
            from backend.routes.ws import get_broadcast_manager
            broadcast_event = dict(event_data)
            if isinstance(broadcast_event.get("timestamp"), datetime):
                broadcast_event["timestamp"] = broadcast_event["timestamp"].isoformat()
            manager = get_broadcast_manager()
            await manager.broadcast({
                "type": "security_event",
                "event": broadcast_event,
            })
        except Exception as exc:
            log.debug("audit.ws.broadcast_failed", error=str(exc))

    def _write_fallback(self, event_data: dict[str, Any]) -> None:
        """Write event as JSON line to fallback log file."""
        try:
            serializable = dict(event_data)
            if isinstance(serializable.get("timestamp"), datetime):
                serializable["timestamp"] = serializable["timestamp"].isoformat()

            line = json.dumps(serializable) + "\n"
            fallback_file = Path(self.fallback_path)
            with fallback_file.open("a", encoding="utf-8") as f:
                f.write(line)
            log.warn("audit.fallback.written", path=self.fallback_path, request_id=event_data.get("request_id"))
        except Exception as exc:
            log.critical("audit.fallback.write_failed", error=str(exc))


# Global singleton instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Return the global AuditLogger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def reset_audit_logger() -> None:
    """Reset the global AuditLogger instance (primarily for tests)."""
    global _audit_logger
    _audit_logger = None
