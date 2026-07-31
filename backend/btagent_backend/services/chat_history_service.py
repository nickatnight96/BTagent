"""Investigation chat-transcript persistence + history read (#482 debt).

``agentStore.loadHistory`` has called ``GET /investigations/{id}/history`` on
every workspace open since Phase 1 — and swallowed the 404, because the
endpoint was never built. The reachability guard (#532) turned that silence
into a named debt; this service pays it.

The durable substrate is the existing ``events`` table (``EventRow``), whose
docstring always promised persistence but which nothing wrote. Two event types
make up a transcript:

* ``chat_user`` — written synchronously by ``POST /chat`` (the only place a
  user message enters the system), in the request's own session/commit.
* ``output`` — the agent's finalized answer (``EventType.OUTPUT``, emitted by
  the agents-side hook at ``on_llm_end``). The backend only ever sees it on
  the Redis→WebSocket path, so the WS hub's dispatch chokepoint calls
  :func:`persist_assistant_output` fire-and-forget. Persistence is
  best-effort by design: a failed insert must never stall live streaming,
  so failures log and drop.

Dedup: ``publish`` sends every envelope to both the investigation channel and
the global channel, so dispatch sees each event twice (and a redelivery could
add more). The envelope id is the ``events`` primary key; a second insert is
detected with a pre-check and, under a race, absorbed by the PK constraint.

Token-level ``output_chunk`` events stay ephemeral on purpose — the final
``output`` supersedes them and persisting per-token rows would swamp the
table for zero replay value.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.events import EventEnvelope
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import EventRow

logger = logging.getLogger("btagent.services.chat_history")

# EventRow.type for a user-authored chat message. Not an ``EventType`` member:
# user messages never ride the agent event stream, they enter through the
# chat route and exist only for transcript replay.
CHAT_USER_EVENT = "chat_user"
# ``EventType.OUTPUT.value`` — the agent's finalized answer.
ASSISTANT_EVENT = "output"


async def record_user_message(
    db: AsyncSession, *, investigation_id: str, content: str, user_id: str
) -> EventRow:
    """Persist one user chat message in the caller's session (flush, no commit)."""
    row = EventRow(
        id=generate_id("evt"),
        investigation_id=investigation_id,
        type=CHAT_USER_EVENT,
        data={"content": content, "user_id": user_id},
    )
    db.add(row)
    await db.flush()
    return row


async def persist_assistant_output(
    envelope: EventEnvelope, *, session_factory: Any | None = None
) -> bool:
    """Persist a finalized agent answer from the WS dispatch path.

    Opens its own short-lived session (the hub has none), commits, and
    swallows every failure after logging — live delivery must not depend on
    the transcript write. Returns True when a row was written.
    ``session_factory`` exists for tests; the hub passes nothing and gets the
    app engine's factory.
    """
    text = str(envelope.data.get("text") or "") if isinstance(envelope.data, dict) else ""
    if not text.strip():
        return False

    if session_factory is None:
        from btagent_backend.db.engine import async_session_factory

        session_factory = async_session_factory

    try:
        async with session_factory() as session:
            exists = await session.execute(select(EventRow.id).where(EventRow.id == envelope.id))
            if exists.scalar_one_or_none() is not None:
                return False  # already persisted (dual-channel dispatch)
            session.add(
                EventRow(
                    id=envelope.id,
                    investigation_id=envelope.investigation_id,
                    type=ASSISTANT_EVENT,
                    data={"text": text},
                )
            )
            await session.commit()
            return True
    except IntegrityError:
        return False  # lost the dedup race to the other channel's copy
    except Exception:
        logger.exception(
            "Failed to persist assistant output for investigation %s (event %s)",
            envelope.investigation_id,
            envelope.id,
        )
        return False


async def get_history(db: AsyncSession, *, investigation_id: str) -> list[dict[str, Any]]:
    """The investigation's transcript as the frontend ``ChatMessage[]`` shape."""
    result = await db.execute(
        select(EventRow)
        .where(
            EventRow.investigation_id == investigation_id,
            EventRow.type.in_([CHAT_USER_EVENT, ASSISTANT_EVENT]),
        )
        .order_by(EventRow.timestamp, EventRow.id)
    )
    messages: list[dict[str, Any]] = []
    for row in result.scalars():
        data = row.data or {}
        content = str(data.get("content") if row.type == CHAT_USER_EVENT else data.get("text"))
        if not content or content == "None":
            continue
        messages.append(
            {
                "id": row.id,
                "role": "user" if row.type == CHAT_USER_EVENT else "assistant",
                "content": content,
                "timestamp": row.timestamp.isoformat(),
            }
        )
    return messages
