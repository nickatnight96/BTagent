"""FastAPI WebSocket routes for real-time event streaming."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from btagent_backend.auth.middleware import CurrentUser, get_ws_user

from .hub import ConnectedClient, WebSocketHub
from .protocol import ClientMessage, ClientMessageType, ServerMessage, ServerMessageType

logger = logging.getLogger("btagent.ws.routes")

router = APIRouter(tags=["websocket"])

# The hub instance is injected at app startup via `init_ws_routes`.
_hub: WebSocketHub | None = None


def init_ws_routes(hub: WebSocketHub) -> None:
    """Bind the shared WebSocketHub instance. Called once during app lifespan."""
    global _hub  # noqa: PLW0603
    _hub = hub


def _get_hub() -> WebSocketHub:
    assert _hub is not None, "WebSocket hub not initialised — call init_ws_routes first"
    return _hub


# ---------------------------------------------------------------------------
# Per-investigation WebSocket
# ---------------------------------------------------------------------------


@router.websocket("/ws/investigations/{investigation_id}")
async def ws_investigation(websocket: WebSocket, investigation_id: str) -> None:
    """Stream events for a single investigation. Auth via ?token= query param."""
    hub = _get_hub()

    try:
        user: CurrentUser = await get_ws_user(websocket)
    except Exception:
        # get_ws_user already closed the socket with an error code
        return

    client = await hub.connect(websocket, user, investigation_id=investigation_id)
    if client is None:
        return  # connection limit exceeded; socket already closed

    try:
        await _read_loop(client, hub)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception(
            "Unexpected error on investigation WS user=%s inv=%s",
            user.id,
            investigation_id,
        )
    finally:
        await hub.disconnect(client)


# ---------------------------------------------------------------------------
# Global event stream WebSocket
# ---------------------------------------------------------------------------


@router.websocket("/ws/events")
async def ws_global_events(websocket: WebSocket) -> None:
    """Stream all events across every investigation. Auth via ?token= query param."""
    hub = _get_hub()

    try:
        user: CurrentUser = await get_ws_user(websocket)
    except Exception:
        return

    client = await hub.connect(websocket, user, investigation_id=None)
    if client is None:
        return

    try:
        await _read_loop(client, hub)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception(
            "Unexpected error on global WS user=%s", user.id
        )
    finally:
        await hub.disconnect(client)


# ---------------------------------------------------------------------------
# Shared read loop — handles client messages
# ---------------------------------------------------------------------------


async def _read_loop(client: ConnectedClient, hub: WebSocketHub) -> None:
    while True:
        raw = await client.ws.receive_text()
        try:
            msg = ClientMessage.model_validate_json(raw)
        except Exception:
            err = ServerMessage(
                type=ServerMessageType.ERROR,
                data={"detail": "Invalid message format"},
            ).model_dump_json()
            await client.ws.send_text(err)
            continue

        if msg.type == ClientMessageType.SUBSCRIBE:
            if not msg.investigation_id:
                await _send_error(client, "subscribe requires investigation_id")
                continue
            await hub.subscribe(client, msg.investigation_id)

        elif msg.type == ClientMessageType.UNSUBSCRIBE:
            if not msg.investigation_id:
                await _send_error(client, "unsubscribe requires investigation_id")
                continue
            await hub.unsubscribe(client, msg.investigation_id)

        elif msg.type == ClientMessageType.CHAT:
            if not msg.investigation_id:
                await _send_error(client, "chat requires investigation_id")
                continue
            # Forward to the agent engine via Redis (fire-and-forget).
            redis = hub._redis
            if redis:
                payload = json.dumps(
                    {
                        "type": "chat",
                        "investigation_id": msg.investigation_id,
                        "user_id": client.user.id,
                        "username": client.user.username,
                        "data": msg.data,
                    }
                )
                await redis.publish(
                    f"btagent:commands:{msg.investigation_id}", payload
                )

        elif msg.type == ClientMessageType.HITL_RESPONSE:
            if not msg.investigation_id:
                await _send_error(client, "hitl_response requires investigation_id")
                continue
            redis = hub._redis
            if redis:
                payload = json.dumps(
                    {
                        "type": "hitl_response",
                        "investigation_id": msg.investigation_id,
                        "user_id": client.user.id,
                        "username": client.user.username,
                        "data": msg.data,
                    }
                )
                await redis.publish(
                    f"btagent:commands:{msg.investigation_id}", payload
                )

        else:
            await _send_error(client, f"Unknown message type: {msg.type}")


async def _send_error(client: ConnectedClient, detail: str) -> None:
    msg = ServerMessage(
        type=ServerMessageType.ERROR,
        data={"detail": detail},
    ).model_dump_json()
    await client.ws.send_text(msg)
