"""Unified long-term Agent Memory service (#482) — the FOUNDATIONAL slice.

Provides the read/write interface over :class:`AgentMemoryRow`: a first-class
store of COMPACT STRUCTURED FACTS (``entity_note`` / ``decision`` / ``learning``
/ ``observation``) that agents accrue and recall across investigations. It sits
alongside — and does not replace — the existing scattered stores (RAG
knowledge, weak signals, behavioral baselines, org profile).

Three public surfaces:

* :class:`MemoryService` — ``record_memory`` (org+kind+subject upsert) and
  ``recall_memories`` (strictly org-scoped, recency-ranked, TLP-aware).
* :func:`render_for_prompt` — renders recalled memories into a fenced
  ``<agent-memory>`` block, mirroring ``org_profile.render_for_prompt`` so an
  investigation's entity memories surface alongside org context in agent
  prompts.
* :func:`record_investigation_close_memories` — the best-effort auto-write hook
  fired at investigation close (an ``entity_note`` per key entity plus a
  ``decision`` memory for the disposition).

Deferred (see #482): pgvector semantic recall, consolidation/summarization, any
frontend/UI, and migrating the scattered stores behind this interface.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from btagent_shared.security import tlp_rank
from btagent_shared.types.config import TLP
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_memory import MEMORY_KINDS, AgentMemoryRow

if TYPE_CHECKING:
    from btagent_backend.db.models import InvestigationRow

logger = logging.getLogger("btagent.services.memory")

# Default number of memories a single recall returns.
DEFAULT_RECALL_LIMIT = 20

# Cap on how many entity notes the close-hook records per investigation, so a
# noisy case can't flood the store.
_MAX_CLOSE_ENTITY_NOTES = 25


def _coerce_tlp(value: TLP | str | None, *, default: TLP, fail_closed: TLP) -> TLP:
    """Resolve *value* to a concrete :class:`TLP`.

    ``None`` resolves to *default*; a supplied-but-unrecognised value resolves
    to *fail_closed* (never silently to a more permissive level).
    """
    if value is None:
        return default
    if isinstance(value, TLP):
        return value
    try:
        return TLP(str(value).lower())
    except ValueError:
        return fail_closed


def _allowed_tlp_values(caller_tlp: TLP) -> list[str]:
    """TLP string values a caller cleared at *caller_tlp* is permitted to see.

    A caller sees any memory whose restriction rank is at or below their
    clearance rank; anything more restricted is withheld. Unknown/garbage
    stored ``tlp_level`` strings are simply not in this set, so they fail
    closed (are never returned).
    """
    ceiling = tlp_rank(caller_tlp)
    return [t.value for t in TLP if tlp_rank(t) <= ceiling]


class MemoryService:
    """Read/write interface over the unified long-term memory store."""

    async def record_memory(
        self,
        session: AsyncSession,
        *,
        org_id: str = DEFAULT_ORG_ID,
        kind: str,
        subject: str,
        content: str,
        source: str = "",
        confidence: float | None = None,
        tlp_level: TLP | str = TLP.GREEN,
    ) -> AgentMemoryRow:
        """Upsert a memory keyed by ``(org_id, kind, subject)``.

        A matching row has its ``content`` / ``source`` / ``confidence`` /
        ``tlp_level`` overwritten and ``updated_at`` bumped; otherwise a new
        row is inserted. The row is flushed (not committed) — the caller owns
        the transaction.
        """
        if kind not in MEMORY_KINDS:
            raise ValueError(
                f"Unknown memory kind {kind!r}; expected one of {sorted(MEMORY_KINDS)}"
            )
        if not subject:
            raise ValueError("memory subject must be a non-empty string")

        tlp = _coerce_tlp(tlp_level, default=TLP.GREEN, fail_closed=TLP.RED)
        now = datetime.now(UTC)

        result = await session.execute(
            select(AgentMemoryRow).where(
                AgentMemoryRow.org_id == org_id,
                AgentMemoryRow.kind == kind,
                AgentMemoryRow.subject == subject,
            )
        )
        row = result.scalar_one_or_none()

        if row is not None:
            row.content = content
            row.source = source
            row.confidence = confidence
            row.tlp_level = tlp.value
            row.updated_at = now
            logger.debug(
                "Updated memory %s (org=%s kind=%s subject=%r)", row.id, org_id, kind, subject
            )
        else:
            row = AgentMemoryRow(
                id=generate_id("mem"),
                org_id=org_id,
                kind=kind,
                subject=subject,
                content=content,
                source=source,
                confidence=confidence,
                tlp_level=tlp.value,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            logger.debug(
                "Recorded memory %s (org=%s kind=%s subject=%r)", row.id, org_id, kind, subject
            )

        await session.flush()
        return row

    async def recall_memories(
        self,
        session: AsyncSession,
        org_id: str,
        *,
        subject: str | None = None,
        kind: str | None = None,
        limit: int = DEFAULT_RECALL_LIMIT,
        caller_tlp: TLP | str = TLP.GREEN,
    ) -> list[AgentMemoryRow]:
        """Return recency-ranked memories for *org_id*, TLP-filtered.

        Strictly org-scoped: only rows for *org_id* are considered — a caller
        can never recall another tenant's memory. TLP-aware: a memory whose
        ``tlp_level`` is more restricted than *caller_tlp*'s clearance is never
        returned. Results are ordered most-recently-updated first and capped at
        *limit*.
        """
        clearance = _coerce_tlp(caller_tlp, default=TLP.GREEN, fail_closed=TLP.WHITE)

        stmt = select(AgentMemoryRow).where(
            AgentMemoryRow.org_id == org_id,
            AgentMemoryRow.tlp_level.in_(_allowed_tlp_values(clearance)),
        )
        if subject is not None:
            stmt = stmt.where(AgentMemoryRow.subject == subject)
        if kind is not None:
            stmt = stmt.where(AgentMemoryRow.kind == kind)

        stmt = stmt.order_by(AgentMemoryRow.updated_at.desc()).limit(max(1, limit))

        result = await session.execute(stmt)
        return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Prompt rendering
# ---------------------------------------------------------------------------


def _format_memory_line(mem: AgentMemoryRow) -> str:
    meta_parts: list[str] = []
    if mem.source:
        meta_parts.append(f"source={mem.source}")
    if mem.confidence is not None:
        meta_parts.append(f"confidence={mem.confidence:.2f}")
    meta = f" ({', '.join(meta_parts)})" if meta_parts else ""
    return f"[{mem.kind}] {mem.subject}: {mem.content}{meta}"


def render_for_prompt(memories: list[AgentMemoryRow]) -> str:
    """Render recalled memories as a fenced ``<agent-memory>`` block.

    Mirrors ``org_profile.render_for_prompt``'s XML-fenced convention for
    external context in agent prompts. The content is untrusted recalled data,
    so it is wrapped (fenced) rather than interpolated as instructions.
    """
    if not memories:
        body = "No agent memory recorded."
    else:
        body = "\n".join(_format_memory_line(m) for m in memories)
    return f"<agent-memory>\n{body}\n</agent-memory>"


# ---------------------------------------------------------------------------
# Auto-write close hook
# ---------------------------------------------------------------------------


def _extract_entities(final_state: dict[str, Any]) -> list[tuple[str, str]]:
    """Pull ``(ioc_type, value)`` entity pairs out of a final investigation state.

    De-duplicates on value, preserving first-seen order, and caps the count so
    a noisy case can't flood the memory store.
    """
    entities: list[tuple[str, str]] = []
    seen: set[str] = set()
    for ioc in final_state.get("iocs") or []:
        if not isinstance(ioc, dict):
            continue
        value = str(ioc.get("value") or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        entities.append((str(ioc.get("type") or "indicator"), value))
        if len(entities) >= _MAX_CLOSE_ENTITY_NOTES:
            break
    return entities


async def record_investigation_close_memories(
    session: AsyncSession,
    investigation: InvestigationRow,
    final_state: dict[str, Any],
    *,
    service: MemoryService | None = None,
) -> list[AgentMemoryRow]:
    """Record salient long-term memories when an investigation closes.

    Writes an ``entity_note`` per key entity (the investigation's IOCs) plus a
    single ``decision`` memory capturing the disposition. Scoped to the
    investigation's ``org_id`` and tagged with its TLP level. Returns the rows
    recorded (the caller owns commit).

    This is the pure recording logic; the best-effort wrapper that guarantees a
    hook failure never sinks the close lives in the TaskManager.
    """
    svc = service or MemoryService()
    org_id = getattr(investigation, "org_id", DEFAULT_ORG_ID) or DEFAULT_ORG_ID
    inv_id = investigation.id
    tlp_level = getattr(investigation, "tlp_level", None) or final_state.get("tlp_level") or "green"
    disposition = str(final_state.get("status") or getattr(investigation, "status", "") or "closed")
    severity = str(final_state.get("severity") or getattr(investigation, "severity", "") or "")

    recorded: list[AgentMemoryRow] = []

    # One entity_note per key entity — durable per-entity context keyed by the
    # entity value so future investigations touching the same entity recall it.
    for ioc_type, value in _extract_entities(final_state):
        note = (
            f"{ioc_type} observed in investigation {inv_id} "
            f"({investigation.title!r}); disposition={disposition}"
        )
        if severity:
            note += f", severity={severity}"
        recorded.append(
            await svc.record_memory(
                session,
                org_id=org_id,
                kind="entity_note",
                subject=value,
                content=note,
                source=inv_id,
                tlp_level=tlp_level,
            )
        )

    # A decision memory for the disposition, keyed by the investigation id.
    decision_content = (
        f"Investigation {inv_id} ({investigation.title!r}) closed with disposition={disposition}"
    )
    if severity:
        decision_content += f", severity={severity}"
    recorded.append(
        await svc.record_memory(
            session,
            org_id=org_id,
            kind="decision",
            subject=inv_id,
            content=decision_content,
            source=inv_id,
            tlp_level=tlp_level,
        )
    )

    logger.info(
        "Recorded %d close memories for investigation %s (org=%s)",
        len(recorded),
        inv_id,
        org_id,
    )
    return recorded
