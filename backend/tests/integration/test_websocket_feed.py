"""
Integration tests for Phase 10 — WebSocket Live Feed
=====================================================
Tests:
1. Valid WebSocket connection established.
2. Token authentication via query parameter.
3. Invalid token rejection with WS policy violation.
4. Heartbeat ping / pong message cycle.
5. Broadcasting live security events to active clients.
6. Multi-client broadcast distribution.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.auth.service import create_jwt_token
from backend.main import create_app
from backend.routes.ws import get_broadcast_manager


@pytest.fixture
def sync_client():
    app = create_app()
    return TestClient(app)


def test_websocket_connection_unauthenticated(sync_client: TestClient) -> None:
    """In development/test mode, WebSocket accepts connection without token."""
    with sync_client.websocket_connect("/ws/security-events") as ws:
        data = ws.receive_json()
        assert data["type"] == "connection_established"
        assert "timestamp" in data


def test_websocket_connection_authenticated(sync_client: TestClient) -> None:
    """WebSocket accepts connection when valid JWT access token is passed."""
    token, _ = create_jwt_token(
        user_id="analyst_1",
        username="analyst1",
        role="ANALYST",
        token_type="access",
        expires_delta=timedelta(minutes=15),
    )
    with sync_client.websocket_connect(f"/ws/security-events?token={token}") as ws:
        data = ws.receive_json()
        assert data["type"] == "connection_established"


def test_websocket_invalid_token_rejected(sync_client: TestClient) -> None:
    """WebSocket immediately rejects invalid or forged token."""
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with sync_client.websocket_connect("/ws/security-events?token=invalid.jwt.token"):
            pass
    assert exc_info.value.code == 1008  # Policy violation


def test_websocket_ping_pong_heartbeat(sync_client: TestClient) -> None:
    """Sending ping produces pong with timestamp for keep-alive."""
    with sync_client.websocket_connect("/ws/security-events") as ws:
        # Consume welcome message
        ws.receive_json()

        # Send ping
        ws.send_json({"type": "ping"})
        response = ws.receive_json()
        assert response["type"] == "pong"
        assert "timestamp" in response


def test_websocket_broadcast_security_event(sync_client: TestClient) -> None:
    """Broadcast manager successfully delivers security events to connected client."""
    manager = get_broadcast_manager()

    with sync_client.websocket_connect("/ws/security-events") as ws:
        welcome = ws.receive_json()
        assert welcome["type"] == "connection_established"

        # Simulate a security event broadcast
        import asyncio

        event_payload = {
            "type": "security_event",
            "event": {
                "id": "evt-123",
                "request_id": "req-999",
                "source_ip": "192.168.1.50",
                "action": "BLOCKED",
                "risk_score": 85,
                "threats": ["SQL_INJECTION"],
            },
        }

        asyncio.run(manager.broadcast(event_payload))

        received = ws.receive_json()
        assert received["type"] == "security_event"
        assert received["event"]["request_id"] == "req-999"
        assert received["event"]["risk_score"] == 85
        assert received["event"]["action"] == "BLOCKED"


def test_websocket_multiple_clients_receive_broadcast(sync_client: TestClient) -> None:
    """Multiple concurrent WebSocket subscribers each receive broadcast messages."""
    manager = get_broadcast_manager()

    with sync_client.websocket_connect("/ws/security-events") as ws1:
        with sync_client.websocket_connect("/ws/security-events") as ws2:
            # Consume welcome packets
            ws1.receive_json()
            ws2.receive_json()

            import asyncio

            broadcast_msg = {
                "type": "security_event",
                "event": {
                    "request_id": "multi-client-test",
                    "action": "CHALLENGED",
                    "risk_score": 50,
                },
            }
            asyncio.run(manager.broadcast(broadcast_msg))

            msg1 = ws1.receive_json()
            msg2 = ws2.receive_json()

            assert msg1["event"]["request_id"] == "multi-client-test"
            assert msg2["event"]["request_id"] == "multi-client-test"
