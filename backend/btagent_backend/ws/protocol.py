"""WebSocket protocol definitions — message types, envelopes, and channel naming."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from btagent_shared.types.events import EventEnvelope, EventType
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Channel naming
# ---------------------------------------------------------------------------

CHANNEL_PREFIX = "btagent:events"

# Per-user in-app notification channel — the one NotificationService.send_inapp
# publishes to. Kept as a distinct prefix from CHANNEL_PREFIX because the
# payload is a plain notification dict, not an EventEnvelope.
NOTIFICATION_CHANNEL_PREFIX = "btagent:notifications"


def investigation_channel(investigation_id: str) -> str:
    return f"{CHANNEL_PREFIX}:{investigation_id}"


def global_channel() -> str:
    return f"{CHANNEL_PREFIX}:global"


def notification_channel(user_id: str) -> str:
    return f"{NOTIFICATION_CHANNEL_PREFIX}:{user_id}"


# ---------------------------------------------------------------------------
# Client -> Server message types
# ---------------------------------------------------------------------------


class ClientMessageType(StrEnum):
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    CHAT = "chat"
    HITL_RESPONSE = "hitl_response"


class ClientMessage(BaseModel):
    """Envelope for messages sent *from* the browser to the server."""

    type: ClientMessageType
    investigation_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Server -> Client message types
# ---------------------------------------------------------------------------
# Server events are wrapped in ServerMessage and use EventType from shared.


class ServerMessageType(StrEnum):
    """Meta-level server messages (not agent events)."""

    ERROR = "error"
    SUBSCRIBED = "subscribed"
    UNSUBSCRIBED = "unsubscribed"
    PONG = "pong"
    # A per-user in-app notification forwarded from the notification channel
    # (data = the notification dict NotificationService.send_inapp published).
    NOTIFICATION = "notification"


class ServerMessage(BaseModel):
    """Envelope for messages sent *from* the server to the browser.

    Agent events are forwarded as-is using EventEnvelope.model_dump().
    Protocol-level messages (ack, error) use this wrapper.
    """

    type: str  # ServerMessageType or EventType value
    data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Streaming token-by-token helpers
# ---------------------------------------------------------------------------


class OutputChunk(BaseModel):
    """Token-by-token streaming payload (EventType.OUTPUT_CHUNK)."""

    text: str
    index: int
    investigation_id: str


class OutputComplete(BaseModel):
    """Final reassembled output (EventType.OUTPUT_COMPLETE)."""

    full_text: str
    investigation_id: str


# ---------------------------------------------------------------------------
# Backpressure policy
# ---------------------------------------------------------------------------

# Events that MUST be delivered even when the client is slow.
CRITICAL_EVENT_TYPES: frozenset[EventType] = frozenset(
    {
        EventType.HITL_CHECKPOINT,
        EventType.HITL_RESPONSE,
        EventType.HITL_TIMEOUT,
        EventType.ERROR,
        EventType.INVESTIGATION_COMPLETE,
        EventType.INVESTIGATION_FAILED,
        EventType.CONTAINMENT_PROPOSED,
        EventType.CONTAINMENT_APPROVED,
        EventType.CONTAINMENT_EXECUTED,
        EventType.SERVER_SHUTDOWN,
    }
)

# Maximum number of pending events per client before non-critical events
# are dropped.
BACKPRESSURE_QUEUE_LIMIT = 256

# Wave-2 Medium #15: cap inbound WebSocket message size so a malicious client
# cannot exhaust server memory by streaming a single huge frame. Anything
# larger than this triggers a 1009 ("message too big") close.
MAX_WS_MESSAGE_BYTES = 65536  # 64 KiB — well above any legitimate client frame


def is_critical(envelope: EventEnvelope) -> bool:
    return envelope.type in CRITICAL_EVENT_TYPES
