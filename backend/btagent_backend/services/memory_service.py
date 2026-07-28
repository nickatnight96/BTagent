"""Unified long-term Agent Memory service (#482).

Provides the read/write interface over :class:`AgentMemoryRow`: a first-class
store of COMPACT STRUCTURED FACTS (``entity_note`` / ``decision`` / ``learning``
/ ``observation``) that agents accrue and recall across investigations. It sits
alongside — and does not replace — the existing scattered stores (RAG
knowledge, weak signals, behavioral baselines, org profile).

Public surfaces:

* :class:`MemoryService` — ``record_memory`` (org+kind+subject upsert, which
  also generates the row's embedding best-effort), ``recall_memories``
  (strictly org-scoped, recency-ranked, TLP-aware) and ``recall_semantic``
  (the same org + TLP filtering, ranked by embedding cosine similarity).
* :func:`render_for_prompt` — renders recalled memories into a fenced
  ``<agent-memory>`` block, mirroring ``org_profile.render_for_prompt`` so an
  investigation's entity memories surface alongside org context in agent
  prompts.
* :func:`record_investigation_close_memories` — the best-effort auto-write hook
  fired at investigation close (an ``entity_note`` per key entity plus a
  ``decision`` memory for the disposition).
* :func:`consolidate_memories` / :func:`consolidate_all_orgs` — the
  best-effort, org-scoped consolidation pass that collapses near-duplicate
  memories for a subject into the highest-confidence/most-recent survivor and
  stamps the losers ``superseded_at`` (excluded from recall thereafter). Driven
  on a cron by ``scheduler.jobs.memory_consolidation_sweep``.

Two invariants hold on EVERY query path added here, exactly as on the original
recall: results are strictly scoped to a single ``org_id``, and a memory more
restricted than the caller's TLP clearance is never returned (unknown/garbage
``tlp_level`` values fail closed — they match no allowed value).

Semantic recall degrades gracefully: pgvector's distance operators only exist on
PostgreSQL, so on any other dialect (the SQLite unit-test DB, a local sqlite
run) — or if embedding generation fails — ``recall_semantic`` falls back to the
existing recency/subject ranking instead of raising.

Deferred (see #482): any frontend/UI, migrating the scattered stores behind this
interface, and cross-org/global memory.
"""

from __future__ import annotations

import difflib
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from btagent_shared.security import tlp_rank
from btagent_shared.types.config import TLP
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_memory import MEMORY_KINDS, AgentMemoryRow
from btagent_backend.services.embedding_service import (
    EmbeddingService,
    MockEmbeddingService,
)

if TYPE_CHECKING:
    from btagent_backend.db.models import InvestigationRow

logger = logging.getLogger("btagent.services.memory")

# Default number of memories a single recall returns.
DEFAULT_RECALL_LIMIT = 20

# Cap on how many entity notes the close-hook records per investigation, so a
# noisy case can't flood the store.
_MAX_CLOSE_ENTITY_NOTES = 25

# Two memories whose normalised content is at least this similar are treated as
# near-duplicates by consolidation. difflib's ratio is a character-level
# similarity in [0, 1]; 0.85 collapses "same fact, different wording/case id"
# without merging genuinely distinct facts about the same entity.
DEFAULT_CONSOLIDATION_THRESHOLD = 0.85

# Bound the O(n²) similarity comparison inside one (subject, tlp) group.
_MAX_CONSOLIDATION_GROUP = 200

# Cap the merged ``source`` string to the column width.
_MAX_SOURCE_LEN = 256


def _is_postgres(session: AsyncSession) -> bool:
    """True when *session* is bound to PostgreSQL.

    pgvector's ``<=>`` / ``<->`` operators do not exist on SQLite (the backend
    unit-test DB), so the vector path must only be emitted on PostgreSQL. Any
    problem resolving the bind is treated as "not PostgreSQL" — the caller then
    falls back to recency ranking, which is always correct, just less
    associative.
    """
    try:
        bind = session.get_bind()
    except Exception:  # pragma: no cover - defensive: unbound/odd session
        return False
    return getattr(getattr(bind, "dialect", None), "name", "") == "postgresql"


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


def _scope_clauses(
    org_id: str,
    clearance: TLP,
    *,
    subject: str | None = None,
    kind: str | None = None,
    live_only: bool = True,
) -> list[Any]:
    """Build the WHERE clauses EVERY recall path must apply.

    Single source of truth for the security-critical filters so the semantic
    path cannot drift from the recency path: strict single-org scoping, TLP
    fail-closed clearance filtering, and (by default) excluding rows
    consolidation has superseded.
    """
    clauses: list[Any] = [
        AgentMemoryRow.org_id == org_id,
        AgentMemoryRow.tlp_level.in_(_allowed_tlp_values(clearance)),
    ]
    if live_only:
        clauses.append(AgentMemoryRow.superseded_at.is_(None))
    if subject is not None:
        clauses.append(AgentMemoryRow.subject == subject)
    if kind is not None:
        clauses.append(AgentMemoryRow.kind == kind)
    return clauses


def _embedding_text(kind: str, subject: str, content: str) -> str:
    """The text a memory row is embedded from.

    Subject + content (kind as a light prefix) so a query about an entity
    matches both the entity handle and the fact body.
    """
    return f"{kind} {subject}: {content}"


class MemoryService:
    """Read/write interface over the unified long-term memory store."""

    def __init__(
        self,
        embedding_service: EmbeddingService | None = None,
        *,
        embedding_factory: Callable[[], EmbeddingService] | None = None,
    ) -> None:
        # The embedder is built LAZILY, mirroring ``KnowledgeService`` (GH
        # #383). Every pure-DB path (recall by subject, consolidation, the
        # close hook) must work with no embedding provider configured, so
        # construction can never depend on one. ``_require_embedder`` resolves
        # it on first actual use via ``embedding_factory``, defaulting to the
        # deterministic :class:`MockEmbeddingService` so the store works with
        # no API key at all. An explicit ``embedding_service`` wins and is used
        # verbatim (tests inject a mock/raising service this way).
        self._embedding_service = embedding_service
        self._embedding_factory = embedding_factory

    def _require_embedder(self) -> EmbeddingService:
        """Return the embedding service, building it on first use."""
        if self._embedding_service is None:
            self._embedding_service = (
                self._embedding_factory()
                if self._embedding_factory is not None
                else MockEmbeddingService()
            )
        return self._embedding_service

    async def _embed(self, text: str) -> list[float] | None:
        """Embed *text*, returning ``None`` on any failure.

        Deliberately swallows everything: an embedding is an optimisation for
        recall ranking, never a precondition for recording or reading a
        memory. A missing API key, a provider outage, or a factory that raises
        must NEVER 500 a write or block a recall — the row simply lands with a
        NULL embedding and stays reachable through recency/subject recall.
        """
        if not text.strip():
            return None
        try:
            vectors = await self._require_embedder().generate_embeddings([text])
        except Exception:
            logger.warning(
                "Memory embedding generation failed; recording without an embedding",
                exc_info=True,
            )
            return None
        if not vectors:
            return None
        return list(vectors[0])

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

        The row's semantic ``embedding`` is (re)generated here, best-effort:
        failure to embed logs and leaves the column NULL rather than failing
        the write (see :meth:`_embed`).

        Re-recording a previously consolidated row revives it — ``superseded_at``
        is cleared, because a fact just written is live by definition.
        """
        if kind not in MEMORY_KINDS:
            raise ValueError(
                f"Unknown memory kind {kind!r}; expected one of {sorted(MEMORY_KINDS)}"
            )
        if not subject:
            raise ValueError("memory subject must be a non-empty string")

        tlp = _coerce_tlp(tlp_level, default=TLP.GREEN, fail_closed=TLP.RED)
        now = datetime.now(UTC)
        embedding = await self._embed(_embedding_text(kind, subject, content))

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
            # A row that consolidation had superseded is live again once it is
            # re-recorded; leaving the stamp set would silently hide the fresh
            # write from every recall path.
            row.superseded_at = None
            if embedding is not None:
                row.embedding = embedding
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
                embedding=embedding,
                superseded_at=None,
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
        include_superseded: bool = False,
    ) -> list[AgentMemoryRow]:
        """Return recency-ranked memories for *org_id*, TLP-filtered.

        Strictly org-scoped: only rows for *org_id* are considered — a caller
        can never recall another tenant's memory. TLP-aware: a memory whose
        ``tlp_level`` is more restricted than *caller_tlp*'s clearance is never
        returned. Rows consolidation has superseded are excluded unless
        *include_superseded* is set (audit/debug only). Results are ordered
        most-recently-updated first and capped at *limit*.
        """
        clearance = _coerce_tlp(caller_tlp, default=TLP.GREEN, fail_closed=TLP.WHITE)

        stmt = select(AgentMemoryRow).where(
            *_scope_clauses(
                org_id, clearance, subject=subject, kind=kind, live_only=not include_superseded
            )
        )
        stmt = stmt.order_by(AgentMemoryRow.updated_at.desc()).limit(max(1, limit))

        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def recall_semantic(
        self,
        session: AsyncSession,
        org_id: str,
        query: str,
        *,
        subject: str | None = None,
        kind: str | None = None,
        limit: int = DEFAULT_RECALL_LIMIT,
        caller_tlp: TLP | str = TLP.GREEN,
    ) -> list[AgentMemoryRow]:
        """Return memories for *org_id* ranked by semantic similarity to *query*.

        Embeds *query* and orders by pgvector cosine distance against each
        row's stored ``embedding``, so recall surfaces *associatively relevant*
        memories rather than only exact-subject matches.

        Security invariants are identical to :meth:`recall_memories` and are
        expressed by the SAME shared clause builder (:func:`_scope_clauses`):
        strictly one ``org_id``, TLP fail-closed, superseded rows excluded. The
        vector operator only changes the ORDER BY, never the WHERE.

        Graceful degradation — the vector path is used only when ALL of these
        hold, and otherwise this returns exactly what
        :meth:`recall_memories` would:

        * the session is bound to PostgreSQL (``<=>`` does not exist on
          SQLite, the backend unit-test DB, and would raise);
        * the query embedded successfully (no provider / provider down → no
          vector); and
        * the vector query itself executed (e.g. the ``vector`` extension is
          actually installed).
        """
        clearance = _coerce_tlp(caller_tlp, default=TLP.GREEN, fail_closed=TLP.WHITE)
        capped = max(1, limit)

        async def _fallback(reason: str) -> list[AgentMemoryRow]:
            logger.debug("Semantic recall falling back to recency ranking: %s", reason)
            return await self.recall_memories(
                session,
                org_id,
                subject=subject,
                kind=kind,
                limit=capped,
                caller_tlp=clearance,
            )

        if not query or not query.strip():
            return await _fallback("empty query")
        if not _is_postgres(session):
            return await _fallback("non-PostgreSQL dialect (pgvector operators unavailable)")

        embedding = await self._embed(query)
        if embedding is None:
            return await _fallback("query embedding unavailable")

        stmt = (
            select(AgentMemoryRow)
            .where(
                *_scope_clauses(org_id, clearance, subject=subject, kind=kind, live_only=True),
                AgentMemoryRow.embedding.is_not(None),
            )
            .order_by(AgentMemoryRow.embedding.cosine_distance(embedding))
            .limit(capped)
        )
        try:
            # SAVEPOINT: on PostgreSQL a failed statement aborts the whole
            # transaction ("current transaction is aborted"), which would take
            # the fallback query — and the caller's own work — down with it.
            # Scoping the vector attempt to a savepoint means a pgvector
            # failure rolls back only itself.
            async with session.begin_nested():
                result = await session.execute(stmt)
                rows = list(result.scalars().all())
        except Exception:
            # A pgvector-specific failure (extension missing, dimension
            # mismatch) must degrade, not 500 the caller.
            logger.warning("Semantic memory recall failed; falling back", exc_info=True)
            return await _fallback("vector query error")

        if not rows:
            # Nothing embedded yet for this org (e.g. rows recorded before
            # this slice) — recency recall is still useful.
            return await _fallback("no embedded rows matched")
        return rows


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


# ---------------------------------------------------------------------------
# Consolidation
# ---------------------------------------------------------------------------


@dataclass
class ConsolidationResult:
    """Counts from one consolidation pass (per org, or aggregated)."""

    orgs: int = 0
    scanned: int = 0
    groups: int = 0
    merged: int = 0
    superseded: int = 0
    superseded_ids: list[str] = field(default_factory=list)

    def as_counts(self) -> dict[str, int]:
        """Log/job-friendly counts (drops the id list)."""
        return {
            "orgs": self.orgs,
            "scanned": self.scanned,
            "groups": self.groups,
            "merged": self.merged,
            "superseded": self.superseded,
        }


_WS_RE = re.compile(r"\s+")
_PUNCT_RE = re.compile(r"[^\w\s]")


def _normalise(text: str) -> str:
    """Lower-case, strip punctuation, collapse whitespace — for similarity."""
    return _WS_RE.sub(" ", _PUNCT_RE.sub(" ", (text or "").lower())).strip()


def content_similarity(left: str, right: str) -> float:
    """Character-level similarity of two memory contents, in ``[0, 1]``."""
    a, b = _normalise(left), _normalise(right)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _survivor_sort_key(row: AgentMemoryRow) -> tuple[float, datetime]:
    """Rank rows so the best survivor sorts FIRST under ``reverse=True``.

    Highest confidence wins; ties break on most-recently-updated. A row with no
    confidence recorded ranks below any row that has one.
    """
    conf = row.confidence if row.confidence is not None else -1.0
    updated = row.updated_at or row.created_at or datetime.min.replace(tzinfo=UTC)
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=UTC)
    return (float(conf), updated)


def _merge_sources(survivor: AgentMemoryRow, losers: list[AgentMemoryRow]) -> str:
    """Union the sources of a collapsed cluster, preserving order, capped."""
    seen: list[str] = []
    for row in [survivor, *losers]:
        for part in (row.source or "").split(","):
            part = part.strip()
            if part and part not in seen:
                seen.append(part)
    merged = ",".join(seen)
    return merged[:_MAX_SOURCE_LEN]


def _cluster(rows: list[AgentMemoryRow], threshold: float) -> list[list[AgentMemoryRow]]:
    """Greedily cluster *rows* (best survivor first) by content similarity."""
    clusters: list[list[AgentMemoryRow]] = []
    for row in rows:
        for cluster in clusters:
            if content_similarity(cluster[0].content, row.content) >= threshold:
                cluster.append(row)
                break
        else:
            clusters.append([row])
    return clusters


async def consolidate_memories(
    session: AsyncSession,
    org_id: str,
    *,
    subject: str | None = None,
    kind: str | None = None,
    threshold: float = DEFAULT_CONSOLIDATION_THRESHOLD,
    now: datetime | None = None,
) -> ConsolidationResult:
    """Collapse near-duplicate/stale memories for one org.

    Live (non-superseded) rows are grouped by ``(subject, tlp_level)`` and, in
    each group, clustered by content similarity (see :func:`content_similarity`
    — ``threshold`` is the near-duplicate cut-off). Every cluster of more than
    one row collapses onto a single survivor: the highest-confidence, then
    most-recently-updated row. The survivor absorbs the cluster's best
    confidence and the union of its sources (and its ``updated_at`` moves to the
    consolidation stamp, since the row was just rewritten); every other row is
    stamped ``superseded_at`` and thereby drops out of all recall paths (the
    rows are retained, not deleted, so the collapse stays auditable).

    Two deliberate scoping choices:

    * **Org-scoped.** Only rows for *org_id* are read or written — consolidation
      can never merge one tenant's memory into another's.
    * **Never across TLP.** ``tlp_level`` is part of the group key, so a RED
      fact is never collapsed into a GREEN survivor (which would either leak
      restricted content into a lower-clearance row or silently withhold the
      GREEN fact). Same-classification duplicates are the only ones merged.

    Flushes; the caller owns the commit.
    """
    stamp = now or datetime.now(UTC)
    result = ConsolidationResult(orgs=1)

    stmt = select(AgentMemoryRow).where(
        AgentMemoryRow.org_id == org_id,
        AgentMemoryRow.superseded_at.is_(None),
    )
    if subject is not None:
        stmt = stmt.where(AgentMemoryRow.subject == subject)
    if kind is not None:
        stmt = stmt.where(AgentMemoryRow.kind == kind)

    rows = list((await session.execute(stmt)).scalars().all())
    result.scanned = len(rows)
    if not rows:
        return result

    groups: dict[tuple[str, str], list[AgentMemoryRow]] = {}
    for row in rows:
        groups.setdefault((row.subject, row.tlp_level), []).append(row)

    for (grp_subject, grp_tlp), grp_rows in groups.items():
        if len(grp_rows) < 2:
            continue
        # Best survivor first, and bound the O(n²) comparison.
        ordered = sorted(grp_rows, key=_survivor_sort_key, reverse=True)[:_MAX_CONSOLIDATION_GROUP]
        for cluster in _cluster(ordered, threshold):
            if len(cluster) < 2:
                continue
            survivor, losers = cluster[0], cluster[1:]
            result.groups += 1
            result.merged += 1

            confidences = [r.confidence for r in cluster if r.confidence is not None]
            if confidences:
                survivor.confidence = max(confidences)
            survivor.source = _merge_sources(survivor, losers)
            survivor.updated_at = stamp

            for loser in losers:
                loser.superseded_at = stamp
                result.superseded += 1
                result.superseded_ids.append(loser.id)

            logger.debug(
                "Consolidated %d memories for org=%s subject=%r tlp=%s onto %s",
                len(cluster),
                org_id,
                grp_subject,
                grp_tlp,
                survivor.id,
            )

    await session.flush()
    if result.superseded:
        logger.info("consolidate_memories(org=%s): %s", org_id, result.as_counts())
    return result


async def consolidate_all_orgs(
    session: AsyncSession,
    *,
    threshold: float = DEFAULT_CONSOLIDATION_THRESHOLD,
    now: datetime | None = None,
) -> ConsolidationResult:
    """Run :func:`consolidate_memories` for every org that has memories.

    Best-effort and per-org isolated: one org's failure is logged and skipped
    rather than aborting the sweep. Multi-tenant by construction — a
    single-``DEFAULT_ORG_ID`` sweep would permanently exclude every other
    tenant's store. The caller owns the commit.
    """
    totals = ConsolidationResult()
    org_ids = [
        org_id
        for (org_id,) in (await session.execute(select(AgentMemoryRow.org_id).distinct())).all()
    ]
    for org_id in org_ids:
        try:
            one = await consolidate_memories(session, org_id, threshold=threshold, now=now)
        except Exception:
            logger.exception("Memory consolidation failed for org %s; continuing", org_id)
            continue
        totals.orgs += 1
        totals.scanned += one.scanned
        totals.groups += one.groups
        totals.merged += one.merged
        totals.superseded += one.superseded
        totals.superseded_ids.extend(one.superseded_ids)
    logger.info("consolidate_all_orgs: %s", totals.as_counts())
    return totals
