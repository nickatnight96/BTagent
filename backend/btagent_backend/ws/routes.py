"""FastAPI WebSocket routes for real-time event streaming."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from btagent_backend.auth.middleware import CurrentUser, get_ws_user
from btagent_backend.db.engine import get_session

from .access import AccessDenied, _inv_org_id, assert_can_subscribe, close_with_access_denied
from .hub import ConnectedClient, WebSocketHub
from .protocol import (
    MAX_WS_MESSAGE_BYTES,
    ClientMessage,
    ClientMessageType,
    ServerMessage,
    ServerMessageType,
)

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
    """Stream events for a single investigation. Auth via ?token= query param.

    Phase B2 (auth-hardening): the caller is authorized via
    :func:`assert_can_subscribe` *before* the hub is allowed to register the
    socket. Failure closes the WS with code 4404 ("not found") to avoid
    leaking the existence of investigations in other orgs.
    """
    hub = _get_hub()

    try:
        user: CurrentUser = await get_ws_user(websocket)
    except Exception:
        # get_ws_user already closed the socket with an error code
        return

    # ---- Authorization gate (Phase B2) -----------------------------------
    # Acquire a short-lived session just for the access check; the hub does
    # not need a session to operate.
    org_id: str | None = None
    try:
        # ``get_session`` is an async generator — use ``__anext__`` so we
        # take exactly one session and let it close when this function
        # returns / on garbage collection.
        gen = get_session()
        db = await gen.__anext__()
        try:
            inv = await assert_can_subscribe(db, user, investigation_id)
            org_id = _inv_org_id(inv)
        finally:
            await gen.aclose()
    except AccessDenied as exc:
        await close_with_access_denied(websocket, exc)
        return
    except Exception:
        # Unexpected DB error — fail closed.
        logger.exception(
            "ws_investigation access check error user=%s inv=%s", user.id, investigation_id
        )
        try:
            await websocket.close(code=1011, reason="internal error")
        except Exception:
            pass
        return

    client = await hub.connect(
        websocket,
        user,
        investigation_id=investigation_id,
        org_id=org_id,
    )
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
    """Stream all events across every investigation. Auth via ?token= query param.

    The global stream still requires a valid JWT but does not bind to a
    specific investigation. Per-client org filtering in the hub ensures that
    events with a different ``org_id`` are not delivered to this client even
    if they land on the global Redis channel.
    """
    hub = _get_hub()

    try:
        user: CurrentUser = await get_ws_user(websocket)
    except Exception:
        return

    # Best-effort capture of user's org_id so per-client dispatch filtering
    # works on the global stream. ``None`` is a no-op same-org default.
    user_org_id = getattr(user, "org_id", None)

    client = await hub.connect(websocket, user, investigation_id=None, org_id=user_org_id)
    if client is None:
        return

    try:
        await _read_loop(client, hub)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("Unexpected error on global WS user=%s", user.id)
    finally:
        await hub.disconnect(client)


# ---------------------------------------------------------------------------
# Shared read loop — handles client messages
# ---------------------------------------------------------------------------


async def _read_loop(client: ConnectedClient, hub: WebSocketHub) -> None:
    while True:
        raw = await client.ws.receive_text()

        # Wave-2 Medium #15: hard cap on inbound frame size. Anything past the
        # cap is treated as a protocol violation — close with 1009 ("message
        # too big") and stop reading. Raise WebSocketDisconnect *after* the
        # close so the route's outer ``except WebSocketDisconnect`` short-
        # circuits ``hub.disconnect``'s fallback ``ws.close()`` (no code),
        # which would otherwise overwrite the 1009 with a default 1000 close
        # before the client read drained the close frame.
        if len(raw.encode("utf-8")) > MAX_WS_MESSAGE_BYTES:
            try:
                await client.ws.close(code=1009, reason="message too big")
            except Exception:
                pass
            raise WebSocketDisconnect(code=1009, reason="message too big")

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
            # Re-run the access check for late subscriptions on the same
            # connection (e.g. from /ws/events). Without this, an analyst
            # could connect to /ws/events and then subscribe to any
            # investigation channel.
            try:
                gen = get_session()
                db = await gen.__anext__()
                try:
                    await assert_can_subscribe(db, client.user, msg.investigation_id)
                finally:
                    await gen.aclose()
            except AccessDenied:
                await _send_error(client, "Permission denied")
                continue
            except Exception:
                await _send_error(client, "Subscription check failed")
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
            # SEC-006 FIX: Enforce RBAC permission for chat messages
            if not client.user.has_permission("investigation:chat"):
                await _send_error(client, "Permission denied: investigation:chat")
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
                await redis.publish(f"btagent:commands:{msg.investigation_id}", payload)

        elif msg.type == ClientMessageType.HITL_RESPONSE:
            if not msg.investigation_id:
                await _send_error(client, "hitl_response requires investigation_id")
                continue
            # SEC-006 FIX: Enforce RBAC permission for HITL approvals
            if not client.user.has_permission("hitl:approve"):
                await _send_error(
                    client, "Permission denied: hitl:approve requires senior_analyst or higher"
                )
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
                await redis.publish(f"btagent:commands:{msg.investigation_id}", payload)

        else:
            await _send_error(client, f"Unknown message type: {msg.type}")


async def _send_error(client: ConnectedClient, detail: str) -> None:
    msg = ServerMessage(
        type=ServerMessageType.ERROR,
        data={"detail": detail},
    ).model_dump_json()
    await client.ws.send_text(msg)
