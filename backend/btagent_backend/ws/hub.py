"""WebSocket connection hub — manages clients, Redis pub/sub fan-out, backpressure."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

from btagent_shared.security import TLPViolation, assert_tlp_allows_egress
from btagent_shared.types.events import EventEnvelope, EventType
from fastapi import WebSocket, WebSocketDisconnect
from redis.asyncio import Redis
from starlette.websockets import WebSocketState

from btagent_backend.auth.middleware import CurrentUser

from .protocol import (
    BACKPRESSURE_QUEUE_LIMIT,
    NOTIFICATION_CHANNEL_PREFIX,
    ServerMessage,
    ServerMessageType,
    global_channel,
    investigation_channel,
    is_critical,
    notification_channel,
)

logger = logging.getLogger("btagent.ws.hub")

# ---------------------------------------------------------------------------
# Per-connection bookkeeping
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class ConnectedClient:
    # ``eq=False`` so the dataclass keeps the default ``__hash__`` based on
    # object identity, which is what the hub's ``set[ConnectedClient]``
    # collections need. (A custom ``__eq__`` would otherwise make it
    # unhashable.)
    ws: WebSocket
    user: CurrentUser
    # Org of the user (or of the investigation they connected to). Captured at
    # connect time so dispatch can filter cross-org events at the per-client
    # layer in addition to the connect-time access check.
    # ``None`` means "no org constraint known" — used as a no-op when Phase A1
    # has not yet populated org_id on users / investigations.
    org_id: str | None = None
    subscriptions: set[str] = field(default_factory=set)
    queue: asyncio.Queue[str] = field(
        default_factory=lambda: asyncio.Queue(BACKPRESSURE_QUEUE_LIMIT)
    )
    _sender_task: asyncio.Task | None = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Hub
# ---------------------------------------------------------------------------


class WebSocketHub:
    """Central coordinator for WebSocket connections and Redis pub/sub fan-out."""

    def __init__(self, redis_url: str, max_connections_per_user: int = 5) -> None:
        self._redis_url = redis_url
        self._max_per_user = max_connections_per_user

        # investigation_id -> set of ConnectedClient
        self._investigation_clients: dict[str, set[ConnectedClient]] = {}
        # all global-stream clients
        self._global_clients: set[ConnectedClient] = set()
        # user_id -> list of ConnectedClient (for per-user limits)
        self._user_connections: dict[str, list[ConnectedClient]] = {}

        self._redis: Redis | None = None
        self._pubsub_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Open Redis connection and begin listening on the global channel."""
        self._redis = Redis.from_url(self._redis_url, decode_responses=True)
        self._pubsub_task = asyncio.create_task(self._pubsub_listener())
        logger.info("WebSocket hub started, listening on Redis pub/sub")

    async def stop(self) -> None:
        """Gracefully shut down: notify clients, cancel listener, close Redis."""
        shutdown_msg = ServerMessage(
            type=ServerMessageType.ERROR,
            data={"detail": "Server shutting down"},
        ).model_dump_json()

        all_clients = list(self._global_clients)
        for client_set in self._investigation_clients.values():
            all_clients.extend(client_set)

        for client in set(all_clients):
            try:
                await client.ws.send_text(shutdown_msg)
            except Exception:
                pass

        if self._pubsub_task and not self._pubsub_task.done():
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                pass

        if self._redis:
            await self._redis.aclose()
            self._redis = None

        logger.info("WebSocket hub stopped")

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(
        self,
        ws: WebSocket,
        user: CurrentUser,
        investigation_id: str | None = None,
        org_id: str | None = None,
    ) -> ConnectedClient | None:
        """Accept a WebSocket and register the client. Returns None if limit exceeded.

        ``org_id`` is captured by the route handler from the access check
        (Phase B2) and recorded on the :class:`ConnectedClient` so dispatch
        can drop events whose payload ``org_id`` field doesn't match.
        """
        async with self._lock:
            user_conns = self._user_connections.setdefault(user.id, [])
            if len(user_conns) >= self._max_per_user:
                await ws.close(
                    code=4029,
                    reason=f"Connection limit ({self._max_per_user}) exceeded",
                )
                return None

            await ws.accept()
            client = ConnectedClient(ws=ws, user=user, org_id=org_id)
            user_conns.append(client)

        client._sender_task = asyncio.create_task(self._sender_loop(client))

        if investigation_id:
            await self.subscribe(client, investigation_id)
        else:
            async with self._lock:
                self._global_clients.add(client)
            await self._ensure_redis_subscription(global_channel())

        return client

    async def disconnect(self, client: ConnectedClient) -> None:
        """Unregister and clean up a client connection."""
        async with self._lock:
            # Remove from investigation subscriptions
            for inv_id in list(client.subscriptions):
                channel = investigation_channel(inv_id)
                clients = self._investigation_clients.get(channel)
                if clients:
                    clients.discard(client)
                    if not clients:
                        del self._investigation_clients[channel]

            self._global_clients.discard(client)

            user_conns = self._user_connections.get(client.user.id, [])
            if client in user_conns:
                user_conns.remove(client)
            if not user_conns:
                self._user_connections.pop(client.user.id, None)

        if client._sender_task and not client._sender_task.done():
            client._sender_task.cancel()
            try:
                await client._sender_task
            except asyncio.CancelledError:
                pass

        try:
            if client.ws.client_state == WebSocketState.CONNECTED:
                await client.ws.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Subscribe / Unsubscribe
    # ------------------------------------------------------------------

    async def subscribe(self, client: ConnectedClient, investigation_id: str) -> None:
        """Subscribe a client to an investigation channel."""
        channel = investigation_channel(investigation_id)
        async with self._lock:
            self._investigation_clients.setdefault(channel, set()).add(client)
            client.subscriptions.add(investigation_id)

        await self._ensure_redis_subscription(channel)

        ack = ServerMessage(
            type=ServerMessageType.SUBSCRIBED,
            data={"investigation_id": investigation_id},
        ).model_dump_json()
        await self._enqueue(client, ack, critical=True)

    async def unsubscribe(self, client: ConnectedClient, investigation_id: str) -> None:
        """Unsubscribe a client from an investigation channel."""
        channel = investigation_channel(investigation_id)
        async with self._lock:
            clients = self._investigation_clients.get(channel)
            if clients:
                clients.discard(client)
                if not clients:
                    del self._investigation_clients[channel]
            client.subscriptions.discard(investigation_id)

        ack = ServerMessage(
            type=ServerMessageType.UNSUBSCRIBED,
            data={"investigation_id": investigation_id},
        ).model_dump_json()
        await self._enqueue(client, ack, critical=True)

    # ------------------------------------------------------------------
    # Publishing (called by backend services to push into Redis)
    # ------------------------------------------------------------------

    async def publish(self, envelope: EventEnvelope) -> int:
        """Publish an event into Redis pub/sub for fan-out.

        Returns the number of subscribers that received the message.

        TLP egress gate: applied here (send side) as defence-in-depth so
        RED data never even reaches Redis when the publisher is in-process
        (e.g. the ``tlp_alert_sink``). The primary chokepoint is
        :meth:`_dispatch` (receive side), which also catches events that
        were published directly to Redis by other clients of the channel
        such as ``RedisEmitter`` (used by ``task_manager`` and the legacy
        agent hooks). Publishing is fire-and-forget, so a blocked event is
        logged + dropped rather than raised back to the emitter.
        """
        if self._should_drop_for_tlp(envelope, where="publish"):
            return 0

        if not self._redis:
            logger.warning("Hub not started; dropping event %s", envelope.id)
            return 0

        payload = envelope.model_dump_json()
        channel = investigation_channel(envelope.investigation_id)
        count = await self._redis.publish(channel, payload)
        count += await self._redis.publish(global_channel(), payload)
        return count

    def _should_drop_for_tlp(self, envelope: EventEnvelope, *, where: str) -> bool:
        """Return True if *envelope* should be dropped on the ``event_emit`` egress.

        Called from both :meth:`publish` (send side) and :meth:`_dispatch`
        (receive/fan-out side) so direct-to-Redis publishers like
        ``RedisEmitter`` are also gated — without that, the primary agent
        event path bypasses the broadcast chokepoint entirely.

        The TLP-violation alert event is exempt: its ``data.tlp`` is
        ``"red"`` because it describes a blocked egress, but it's
        governance metadata, not RED payload, and it must reach the analyst
        surface precisely when RED was refused. Gating it would
        self-trigger (block -> emit violation -> block -> ...).
        """
        if envelope.type == EventType.TLP_VIOLATION_ATTEMPT:
            return False

        org_id = envelope.data.get("org_id") if isinstance(envelope.data, dict) else None
        try:
            assert_tlp_allows_egress(
                envelope.model_dump(mode="json"),
                "event_emit",
                classification_ctx=(envelope.data if isinstance(envelope.data, dict) else None),
                org_id=org_id,
            )
        except TLPViolation:
            # Already logged + a tlp.violation_attempt event emitted by
            # the shared gate.
            logger.warning(
                "Dropping TLP-restricted event %s (type=%s) at %s",
                envelope.id,
                envelope.type.value,
                where,
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Internal: Redis pub/sub listener
    # ------------------------------------------------------------------

    async def _pubsub_listener(self) -> None:
        """Long-running task that listens to all subscribed Redis channels."""
        assert self._redis is not None
        pubsub = self._redis.pubsub()

        # Subscribe to the global channel at startup
        await pubsub.psubscribe(f"{investigation_channel('*')}")
        await pubsub.subscribe(global_channel())
        # Per-user in-app notifications (NotificationService.send_inapp) —
        # forwarded to that user's connections only.
        await pubsub.psubscribe(f"{notification_channel('*')}")

        try:
            async for message in pubsub.listen():
                if message["type"] not in ("message", "pmessage"):
                    continue

                channel: str = message.get("channel", "")
                # For pmessage, the actual channel is in "channel" key
                if message["type"] == "pmessage":
                    channel = message.get("channel", "")

                raw_data: str = message["data"]
                await self._dispatch(channel, raw_data)
        except asyncio.CancelledError:
            await pubsub.unsubscribe()
            await pubsub.punsubscribe()
            await pubsub.aclose()
            raise
        except Exception:
            logger.exception("Redis pub/sub listener crashed")

    async def _dispatch(self, channel: str, raw_json: str) -> None:
        """Route a Redis message to the appropriate WebSocket clients.

        TLP egress gate (primary chokepoint): every event reaching a
        client passes through here, regardless of publisher. ``RedisEmitter``
        (and any other direct-to-Redis publisher) bypasses :meth:`publish`,
        so without this check a RED-tagged event from ``task_manager`` or a
        legacy agent hook would still reach subscribers.
        """
        # Per-user notification channels carry a plain notification dict (not
        # an EventEnvelope) and are user-targeted, so they take a dedicated
        # branch before envelope parsing. Payloads are authored by
        # NotificationService (title/message metadata), and delivery is scoped
        # to the channel's own user — the same data that user already reads
        # via GET /notifications.
        if channel.startswith(f"{NOTIFICATION_CHANNEL_PREFIX}:"):
            await self._dispatch_notification(channel, raw_json)
            return

        try:
            envelope = EventEnvelope.model_validate_json(raw_json)
        except Exception:
            logger.warning("Ignoring unparsable event on channel %s", channel)
            return

        if self._should_drop_for_tlp(envelope, where=f"dispatch({channel})"):
            return

        critical = is_critical(envelope)

        # Phase B2: extract event's org_id (if present) so dispatch can filter
        # at the per-client layer. This is in addition to — not a replacement
        # for — the connect-time access check in ``access.assert_can_subscribe``.
        # Events emitted by Phase 0+ already carry data["org_id"] in most
        # paths; when absent we fall back to a same-org no-op (skip filter).
        event_org_id: str | None = None
        try:
            event_org_id = envelope.data.get("org_id") if isinstance(envelope.data, dict) else None
        except Exception:
            event_org_id = None

        if channel == global_channel():
            async with self._lock:
                targets = list(self._global_clients)
        else:
            async with self._lock:
                targets = list(self._investigation_clients.get(channel, set()))

        for client in targets:
            if not self._client_passes_org_filter(client, event_org_id):
                logger.debug(
                    "Dropping cross-org event for client user=%s client_org=%s event_org=%s",
                    client.user.id,
                    client.org_id,
                    event_org_id,
                )
                continue
            await self._enqueue(client, raw_json, critical=critical)

    @staticmethod
    def _client_passes_org_filter(client: ConnectedClient, event_org_id: str | None) -> bool:
        """Return True if the event may be delivered to this client.

        Conservative: when either side is missing org info we deliver the
        event (same-org no-op). The primary security gate is the connect-time
        access check; this is a defence-in-depth filter for any leaked
        cross-org event that ever lands on a shared channel.
        """
        if client.org_id is None or event_org_id is None:
            return True
        return client.org_id == event_org_id

    async def _dispatch_notification(self, channel: str, raw_json: str) -> None:
        """Forward a per-user notification to that user's connections only.

        The channel suffix IS the target user id
        (``btagent:notifications:{user_id}``), so delivery is inherently
        user-scoped — no org filter needed. The payload is wrapped in a
        ``ServerMessage`` (``type="notification"``) so the browser client can
        distinguish it from agent EventEnvelopes. Enqueued as critical: bell
        pings are rare and small, and must survive backpressure drops.
        """
        user_id = channel.removeprefix(f"{NOTIFICATION_CHANNEL_PREFIX}:")
        if not user_id:
            return

        try:
            payload = json.loads(raw_json)
        except Exception:
            logger.warning("Ignoring unparsable notification on channel %s", channel)
            return
        if not isinstance(payload, dict):
            return

        message = ServerMessage(type=ServerMessageType.NOTIFICATION, data=payload).model_dump_json()

        async with self._lock:
            targets = list(self._user_connections.get(user_id, []))
        for client in targets:
            await self._enqueue(client, message, critical=True)

    # ------------------------------------------------------------------
    # Internal: per-client sender loop with backpressure
    # ------------------------------------------------------------------

    async def _enqueue(self, client: ConnectedClient, payload: str, *, critical: bool) -> None:
        if client.queue.full():
            if critical:
                # Drop the oldest non-critical item to make room
                drained: list[str] = []
                while not client.queue.empty():
                    try:
                        drained.append(client.queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                # Re-add critical items, drop non-critical
                for item in drained:
                    try:
                        env = EventEnvelope.model_validate_json(item)
                        if is_critical(env):
                            client.queue.put_nowait(item)
                    except Exception:
                        # Protocol ack messages — keep them
                        client.queue.put_nowait(item)
                client.queue.put_nowait(payload)
            else:
                # Non-critical event and queue full — drop silently
                logger.debug(
                    "Dropping non-critical event for slow client user=%s",
                    client.user.id,
                )
                return
        else:
            client.queue.put_nowait(payload)

    async def _sender_loop(self, client: ConnectedClient) -> None:
        try:
            while True:
                payload = await client.queue.get()
                try:
                    await client.ws.send_text(payload)
                except (WebSocketDisconnect, RuntimeError):
                    break
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Sender loop error for user=%s", client.user.id)

    # ------------------------------------------------------------------
    # Internal: ensure Redis subscription exists
    # ------------------------------------------------------------------

    async def _ensure_redis_subscription(self, channel: str) -> None:
        # Pattern subscription covers all investigation channels;
        # global channel is subscribed at startup. Nothing extra needed
        # because we use psubscribe for investigation channels in the listener.
        pass

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def connection_count(self) -> int:
        total = len(self._global_clients)
        for clients in self._investigation_clients.values():
            total += len(clients)
        return total

    def stats(self) -> dict:
        """Return diagnostic counters."""
        return {
            "global_clients": len(self._global_clients),
            "investigation_channels": len(self._investigation_clients),
            "total_connections": self.connection_count,
            "users_connected": len(self._user_connections),
        }
