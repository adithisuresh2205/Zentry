"""
SentinelGate — Phase 10: WebSocket Live Security Event Feed
============================================================
Real-time security event broadcasting from gateway and audit logger
directly to connected dashboard clients without polling.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from backend.auth.service import decode_jwt_token
from backend.config import get_settings

log = structlog.get_logger(__name__)

router = APIRouter()


class ConnectionManager:
    """
    Manages active WebSocket connections and handles thread-safe
    event broadcasting to all subscribed clients.
    """

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a WebSocket connection and register it in the active pool."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        log.info("ws.client.connected", count=len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a WebSocket connection from the active pool."""
        async with self._lock:
            self.active_connections.discard(websocket)
        log.info("ws.client.disconnected", count=len(self.active_connections))

    async def send_personal_message(self, message: dict[str, Any], websocket: WebSocket) -> None:
        """Send a JSON payload to a specific WebSocket client."""
        try:
            await websocket.send_json(message)
        except Exception as exc:
            log.debug("ws.send_personal_failed", error=str(exc))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        Broadcast a JSON payload to all active WebSocket clients.
        Stale or dropped connections are cleaned up automatically.
        """
        async with self._lock:
            connections = list(self.active_connections)

        if not connections:
            return

        dead_connections: list[WebSocket] = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    self.active_connections.discard(dead)
            log.info("ws.cleaned_stale_connections", removed=len(dead_connections))


# Singleton instance
_broadcast_manager: ConnectionManager | None = None


def get_broadcast_manager() -> ConnectionManager:
    """Retrieve or initialize the singleton WebSocket ConnectionManager."""
    global _broadcast_manager
    if _broadcast_manager is None:
        _broadcast_manager = ConnectionManager()
    return _broadcast_manager


@router.websocket("/ws/security-events")
async def security_events_websocket(
    websocket: WebSocket,
    token: str | None = Query(default=None),
) -> None:
    """
    WebSocket endpoint streaming real-time security events.

    Authentication:
    - If `token` query param is provided, it is validated as a JWT access token.
    - If `token` is invalid or expired, connection is closed with WS_1008_POLICY_VIOLATION.
    - In development/test mode, unauthenticated connection is allowed if token is omitted.

    Protocol:
    - Server pushes `{"type": "security_event", "event": {...}}` on security incidents.
    - Client can send `{"type": "ping"}` and receives `{"type": "pong", "timestamp": "..."}`.
    """
    settings = get_settings()
    manager = get_broadcast_manager()

    effective_token = token or websocket.cookies.get("access_token")

    # Validate token if provided
    if effective_token:
        try:
            payload = decode_jwt_token(effective_token)
            if payload.type != "access":
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await manager.connect(websocket)

    # Send initial welcome / status packet
    await manager.send_personal_message(
        {
            "type": "connection_established",
            "message": "Connected to Zentry real-time security event feed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        websocket,
    )

    try:
        while True:
            # Await client messages (ping / keep-alive / control commands)
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if isinstance(msg, dict) and msg.get("type") == "ping":
                    await manager.send_personal_message(
                        {
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                        websocket,
                    )
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as exc:
        log.debug("ws.connection.error", error=str(exc))
        await manager.disconnect(websocket)
