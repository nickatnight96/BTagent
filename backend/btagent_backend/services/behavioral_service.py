"""Behavioral Hunter service (Phase 6 #114).

Persistence + detection wiring for the baseline-driven hunt mode.
Decisions (cosine distance, frequency-floor comparison, centroid update)
live in the pure logic in :mod:`btagent_shared.hunt.behavioral`; this
module is the side-effectful shell that loads rows, calls that logic, and
writes back.

Per the codebase convention, this service does **not** commit — the route
layer / agent hook / arq job owns that. Embedding generation and EDR
telemetry ingestion are also out of scope here: the service accepts
pre-computed vectors + pattern keys so it's testable without a real
embedding provider, and the IntentClassifier LLM chain plugs in via
:func:`set_intent` rather than being baked in.

It *does* emit one event — ``behavioral_outlier_detected`` on a fresh
detection — because ``detect_outlier`` has several callers (the OCSF
consumer, the scheduler, the API) and none of them is a natural single
choke-point. Emission follows the ``tlp_alert_sink`` precedent: build an
``EventEnvelope`` and hand it to the WebSocket hub, which fans out to the
global channel. It is strictly best-effort — no hub (unit tests, a worker
with no app lifespan) or a Redis hiccup must never fail a detection that is
already persisted — and callers can turn it off with ``emit_event=False``.

The centroid is a fixed-width pgvector ``Vector(1536)`` column, so all
vectors are normalised to that width on the way in (see
:func:`_to_centroid_vector`) and cross-entity nearest-neighbour search
(:func:`find_similar_profiles`) runs on PostgreSQL's HNSW index, degrading
to an in-Python scan wherever pgvector's operators don't exist.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from btagent_shared.hunt import behavioral as behavioral_logic
from btagent_shared.types.behavioral import (
    EntityKind,
    IntentLabel,
    ProfileType,
)
from btagent_shared.types.hunt_finding import HuntEntity, RecordFindingRequest
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_behavioral import (
    CENTROID_DIM,
    BehavioralEntityRow,
    BehavioralOutlierRow,
    BehavioralProfileRow,
)
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.behavioral")

# Bound on the fallback (non-pgvector) similarity scan so a large org can't
# turn a degraded nearest-neighbour query into a full-table sort in Python.
_MAX_FALLBACK_SCAN = 500


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _is_postgres(session: AsyncSession) -> bool:
    """True when *session* is bound to PostgreSQL.

    pgvector's ``<=>`` / ``<->`` operators do not exist on SQLite (the backend
    unit-test DB), so the vector path must only be emitted on PostgreSQL. Any
    problem resolving the bind is treated as "not PostgreSQL" — the caller then
    falls back to the in-Python scan, which is always correct, just slower.

    Mirrors ``memory_service._is_postgres`` (the established pattern for this
    guard); kept local so the two services stay decoupled.
    """
    try:
        bind = session.get_bind()
    except Exception:  # pragma: no cover - defensive: unbound/odd session
        return False
    return getattr(getattr(bind, "dialect", None), "name", "") == "postgresql"


def _to_centroid_vector(vector: list[float] | None) -> list[float] | None:
    """Normalise *vector* to the fixed ``CENTROID_DIM`` width of the column.

    ``behavioral_profiles.centroid`` is a ``Vector(1536)``: pgvector rejects any
    other width outright, so a shorter vector (a test fixture, or a provider
    that emits fewer dimensions) is **zero-padded** to 1536. Padding is
    deliberately safe for this store's only vector operation, cosine distance:
    appending zeros changes neither the dot product nor either magnitude, so
    ``cosine_distance(pad(a), pad(b)) == cosine_distance(a, b)`` exactly. A
    vector *wider* than the column is a real misconfiguration (wrong embedding
    provider) and raises rather than silently truncating meaning away.
    """
    if vector is None:
        return None
    values = [float(x) for x in vector]
    if len(values) > CENTROID_DIM:
        raise ValueError(
            f"vector of dimension {len(values)} exceeds the centroid column width {CENTROID_DIM}"
        )
    if len(values) < CENTROID_DIM:
        values.extend([0.0] * (CENTROID_DIM - len(values)))
    return values


# --------------------------------------------------------------------------- #
# Entities
# --------------------------------------------------------------------------- #


async def upsert_entity(
    db: AsyncSession,
    *,
    org_id: str,
    kind: EntityKind,
    canonical_id: str,
    enrichment: dict | None = None,
) -> BehavioralEntityRow:
    """Find-or-create the entity for ``(org_id, kind, canonical_id)``.

    On hit, bumps ``last_seen``, merges ``enrichment`` (new keys override), and
    **revives an archived entity** — observing it again is by definition proof
    it is not stale, so ``archived_at`` is cleared and the entity re-enters the
    active baseline pool. On miss, inserts a fresh (active) row.
    """
    now = _utcnow()
    result = await db.execute(
        select(BehavioralEntityRow).where(
            BehavioralEntityRow.org_id == org_id,
            BehavioralEntityRow.kind == kind.value,
            BehavioralEntityRow.canonical_id == canonical_id,
        )
    )
    row = result.scalar_one_or_none()
    if row is not None:
        row.last_seen = now
        if row.archived_at is not None:
            logger.info("reviving archived behavioral entity %s (observed again)", row.id)
            row.archived_at = None
        if enrichment:
            merged = dict(row.enrichment or {})
            merged.update(enrichment)
            row.enrichment = merged
        return row

    row = BehavioralEntityRow(
        id=generate_id("bent"),
        org_id=org_id,
        kind=kind.value,
        canonical_id=canonical_id,
        first_seen=now,
        last_seen=now,
        enrichment=dict(enrichment or {}),
    )
    db.add(row)
    await db.flush()
    return row


# --------------------------------------------------------------------------- #
# Profiles (baseline-build)
# --------------------------------------------------------------------------- #


async def _get_latest_profile(
    db: AsyncSession,
    *,
    entity_id: str,
    profile_type: ProfileType,
) -> BehavioralProfileRow | None:
    result = await db.execute(
        select(BehavioralProfileRow)
        .where(
            BehavioralProfileRow.entity_id == entity_id,
            BehavioralProfileRow.profile_type == profile_type.value,
        )
        .order_by(BehavioralProfileRow.window_end.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def build_baseline(
    db: AsyncSession,
    *,
    entity: BehavioralEntityRow,
    profile_type: ProfileType,
    vectors: list[list[float]],
    pattern_keys: list[str],
    window_start: datetime,
    window_end: datetime,
) -> BehavioralProfileRow:
    """Compute a fresh baseline window from a batch of observed events.

    The centroid is the elementwise mean of ``vectors``; the frequency map
    is the count of ``pattern_keys`` (bounded by the pure-logic helper's
    cap). ``vectors`` and ``pattern_keys`` are independent — a profile_type
    can supply both (cmdline embeddings + the cmdline pattern keys) or just
    one (e.g. process-tree patterns with no vector).

    Always writes a NEW profile row for the window; historical baselines
    are preserved for drift visualisation.

    The persisted centroid is widened to the column's fixed ``CENTROID_DIM``
    (see :func:`_to_centroid_vector`); averaging then padding and padding then
    averaging give the same vector, so the mean is computed on the input width.
    """
    if vectors and not all(len(v) == len(vectors[0]) for v in vectors):
        raise ValueError("all vectors in a baseline batch must share length")

    centroid: list[float] | None = None
    if vectors:
        dim = len(vectors[0])
        sums = [0.0] * dim
        for v in vectors:
            for i, x in enumerate(v):
                sums[i] += x
        centroid = _to_centroid_vector([s / len(vectors) for s in sums])

    freq_map = behavioral_logic.aggregate_pattern_keys(pattern_keys)

    now = _utcnow()
    row = BehavioralProfileRow(
        id=generate_id("bprof"),
        org_id=entity.org_id,
        entity_id=entity.id,
        profile_type=profile_type.value,
        centroid=centroid,
        frequency_map=freq_map,
        pattern_count=len(freq_map),
        sample_size=max(len(vectors), len(pattern_keys)),
        window_start=window_start,
        window_end=window_end,
        computed_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    return row


# --------------------------------------------------------------------------- #
# Outlier detection
# --------------------------------------------------------------------------- #


def _row_to_profile_model(row: BehavioralProfileRow):
    """Build the dependency-free schema for the scorer.

    ``row.centroid`` comes back from pgvector as a numpy array, whose truth
    value is ambiguous — the emptiness check must be an explicit ``is not
    None`` (a bare ``if row.centroid`` raises ``ValueError`` on any array
    longer than one element).
    """
    from btagent_shared.types.behavioral import BehavioralProfile

    return BehavioralProfile(
        id=row.id,
        org_id=row.org_id,
        entity_id=row.entity_id,
        profile_type=ProfileType(row.profile_type),
        centroid=[float(x) for x in row.centroid] if row.centroid is not None else None,
        frequency_map=dict(row.frequency_map or {}),
        pattern_count=row.pattern_count,
        sample_size=row.sample_size,
        window_start=row.window_start,
        window_end=row.window_end,
        computed_at=row.computed_at,
        updated_at=row.updated_at,
    )


async def detect_outlier(
    db: AsyncSession,
    *,
    entity: BehavioralEntityRow,
    profile_type: ProfileType,
    event_id: str,
    event_vector: list[float] | None,
    event_pattern_key: str | None,
    raw_event_excerpt: str = "",
    distance_threshold: float = 0.35,
    frequency_floor: int = 1,
    emit_event: bool = True,
) -> BehavioralOutlierRow | None:
    """Score one event against the entity's latest baseline; persist if outlier.

    Returns the new :class:`BehavioralOutlierRow` (no LLM intent yet —
    populated by :func:`set_intent`), or ``None`` if the event is within
    behavioral bounds. With no baseline yet, returns ``None`` (the scorer
    can't tell signal from "we haven't observed enough" yet, and we'd
    rather under-call than spam).

    On a detection, a ``behavioral_outlier_detected`` event is broadcast so
    ``BehavioralHuntsPage`` surfaces it live instead of waiting up to 30 s for
    the next poll. Emission is best-effort and never affects the return value;
    pass ``emit_event=False`` to suppress it (batch backfills).
    """
    profile_row = await _get_latest_profile(db, entity_id=entity.id, profile_type=profile_type)
    if profile_row is None or profile_row.sample_size == 0:
        return None

    profile = _row_to_profile_model(profile_row)
    is_outlier, distance, rank = behavioral_logic.score_outlier(
        profile,
        # The stored centroid is padded to the column width, so the event
        # vector must be padded identically for the comparison to line up.
        # Zero-padding both sides leaves the cosine distance unchanged.
        _to_centroid_vector(event_vector),
        event_pattern_key,
        distance_threshold=distance_threshold,
        frequency_floor=frequency_floor,
    )
    if not is_outlier:
        return None

    row = BehavioralOutlierRow(
        id=generate_id("bout"),
        org_id=entity.org_id,
        entity_id=entity.id,
        profile_type=profile_type.value,
        event_id=event_id,
        event_pattern_key=event_pattern_key,
        cosine_distance=distance,
        frequency_rank=rank,
        raw_event_excerpt=raw_event_excerpt[:4096],
        created_at=_utcnow(),
    )
    db.add(row)
    await db.flush()

    if emit_event:
        await emit_outlier_detected(row, entity=entity)
    return row


# --------------------------------------------------------------------------- #
# Live surfacing (WebSocket)
# --------------------------------------------------------------------------- #


async def emit_outlier_detected(
    outlier: BehavioralOutlierRow,
    *,
    entity: BehavioralEntityRow,
    hub: object | None = None,
) -> bool:
    """Broadcast a ``behavioral_outlier_detected`` event. Best-effort.

    Follows the ``tlp_alert_sink`` precedent rather than ``RedisEmitter``:
    an outlier belongs to no investigation, and only ``WebSocketHub.publish``
    fans out to the **global** channel that the analyst dashboard's default
    socket listens on (``RedisEmitter`` publishes to a per-investigation
    channel only). ``investigation_id`` therefore carries the stable
    ``"system"`` pseudo-id, exactly as the TLP violation alerter does.

    Security: the payload carries ``org_id`` so the hub's per-client org filter
    (and its TLP egress gate) can act on it, and deliberately carries **no raw
    telemetry** — no ``raw_event_excerpt``, no command line. It is a "something
    changed, refetch" ping; the page then re-reads the outlier through the
    RBAC- and org-scoped ``GET /behavioral/outliers``, so the WS path can never
    widen what an analyst is allowed to see.

    The event is emitted at flush time, before the caller's commit (this
    service never commits). A caller that subsequently rolls back therefore
    leaves a "refetch" ping with nothing behind it — harmless by construction,
    because the payload is a notification, not the data: the page re-reads the
    list and simply finds no new row.

    Returns True when the event was handed to a hub, False otherwise (no hub
    initialised — unit tests, an arq worker with no app lifespan — or a
    publish failure). Never raises: the outlier is already persisted.
    """
    try:
        from btagent_shared.types.events import EventEnvelope, EventType

        if hub is None:
            from btagent_backend.ws.routes import get_hub_optional

            hub = get_hub_optional()
        if hub is None:
            return False

        envelope = EventEnvelope(
            type=EventType.BEHAVIORAL_OUTLIER_DETECTED,
            investigation_id="system",
            data={
                "org_id": entity.org_id,
                "outlier_id": outlier.id,
                "entity_id": entity.id,
                "entity_kind": entity.kind,
                "canonical_id": entity.canonical_id,
                "profile_type": outlier.profile_type,
                "cosine_distance": outlier.cosine_distance,
                "frequency_rank": outlier.frequency_rank,
            },
        )
        await hub.publish(envelope)  # type: ignore[attr-defined]
        return True
    except Exception:
        logger.warning("behavioral outlier event emission failed (non-fatal)", exc_info=True)
        return False


async def get_outlier(db: AsyncSession, outlier_id: str) -> BehavioralOutlierRow | None:
    """Fetch one outlier by id (the route layer owns the org-scoping 404)."""
    return await db.get(BehavioralOutlierRow, outlier_id)


async def list_outliers(
    db: AsyncSession,
    *,
    org_id: str,
    intent_label: IntentLabel | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[BehavioralOutlierRow], int]:
    """Org-scoped, paginated outlier list, newest-first.

    Optionally filtered by ``intent_label`` (``None`` = no filter). Returns the
    page rows plus the total matching count (for the paginated response).
    """
    from sqlalchemy import func

    base = select(BehavioralOutlierRow).where(BehavioralOutlierRow.org_id == org_id)
    if intent_label is not None:
        base = base.where(BehavioralOutlierRow.intent_label == intent_label.value)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = int((await db.execute(count_stmt)).scalar_one())

    page_stmt = (
        base.order_by(BehavioralOutlierRow.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = list((await db.execute(page_stmt)).scalars().all())
    return rows, total


async def set_intent(
    db: AsyncSession,
    *,
    outlier_id: str,
    label: IntentLabel,
    rationale: str,
) -> BehavioralOutlierRow:
    """Persist the IntentClassifier's verdict on an outlier.

    Kept as a separate call so the LLM chain can plug in (or be mocked)
    without coupling detection to model calls.
    """
    row = await db.get(BehavioralOutlierRow, outlier_id)
    if row is None:
        raise ValueError(f"Behavioral outlier not found: {outlier_id}")
    row.intent_label = label.value
    row.intent_rationale = rationale[:4096]
    await db.flush()
    return row


# --------------------------------------------------------------------------- #
# Promotion + closed-loop feedback
# --------------------------------------------------------------------------- #


async def promote_outlier(
    db: AsyncSession,
    *,
    outlier_id: str,
    technique_ids: list[str] | None = None,
) -> str:
    """Escalate a behavioral outlier into the #119 HuntFinding queue.

    Builds a :class:`RecordFindingRequest` from the outlier + its entity
    and persists it via :func:`hunt_triage_service.persist_hunt_findings`
    (so the same cluster-on-insert / suppression-apply path runs). Updates
    the outlier with the new finding id. Returns the finding id.
    """
    outlier = await db.get(BehavioralOutlierRow, outlier_id)
    if outlier is None:
        raise ValueError(f"Behavioral outlier not found: {outlier_id}")
    entity = await db.get(BehavioralEntityRow, outlier.entity_id)
    if entity is None:
        raise ValueError(f"Behavioral entity not found: {outlier.entity_id}")

    severity = "medium"
    if outlier.intent_label == IntentLabel.MALICIOUS.value:
        severity = "high"
    elif outlier.intent_label == IntentLabel.SUSPICIOUS.value:
        severity = "medium"

    # canonical_id can be up to 512 chars; RecordFindingRequest.title caps at
    # 300, so truncate to avoid a ValidationError aborting promotion.
    title = f"Behavioral outlier on {entity.kind}:{entity.canonical_id}"[:300]
    req = RecordFindingRequest(
        source="behavioral",
        domain="behavioral",
        title=title,
        description=outlier.intent_rationale or outlier.raw_event_excerpt or "",
        severity=severity,
        confidence=min(1.0, outlier.cosine_distance),
        technique_ids=list(technique_ids or []),
        entities=[HuntEntity(kind=entity.kind, value=entity.canonical_id)],
        evidence={
            "outlier_id": outlier.id,
            "profile_type": outlier.profile_type,
            "event_id": outlier.event_id,
            "cosine_distance": outlier.cosine_distance,
            "frequency_rank": outlier.frequency_rank,
            "intent_label": outlier.intent_label,
        },
    )
    rows = await hunt_triage_service.persist_hunt_findings(db, org_id=entity.org_id, findings=[req])
    outlier.promoted_to_finding_id = rows[0].id
    await db.flush()
    return rows[0].id


async def feedback_benign(
    db: AsyncSession,
    *,
    outlier_id: str,
) -> BehavioralProfileRow:
    """Closed-loop tuning: fold a benign-triaged outlier back into the baseline.

    Bumps the outlier's pattern in the entity's latest profile frequency map
    (raising the frequency floor for it next time so the same pattern stops
    firing as anomalous). The cmdline embedding centroid is left alone here
    — the next scheduled baseline rebuild will absorb it. Returns the
    updated profile.
    """
    outlier = await db.get(BehavioralOutlierRow, outlier_id)
    if outlier is None:
        raise ValueError(f"Behavioral outlier not found: {outlier_id}")
    if outlier.intent_label != IntentLabel.BENIGN.value:
        raise ValueError(f"feedback_benign called on outlier with intent={outlier.intent_label!r}")

    profile = await _get_latest_profile(
        db,
        entity_id=outlier.entity_id,
        profile_type=ProfileType(outlier.profile_type),
    )
    if profile is None:
        raise ValueError("no baseline profile to fold feedback into")

    # Raise the SAME key the scorer matched on, so the pattern is actually
    # suppressed next time. ``event_pattern_key`` is what ``score_outlier``
    # looks up; fall back to ``event_id`` only for rows written before the
    # column existed.
    pattern_key = outlier.event_pattern_key or outlier.event_id
    profile.frequency_map = behavioral_logic.update_frequency_map(
        dict(profile.frequency_map or {}), pattern_key
    )
    profile.pattern_count = len(profile.frequency_map)
    profile.sample_size = profile.sample_size + 1
    profile.updated_at = _utcnow()
    await db.flush()
    return profile


# --------------------------------------------------------------------------- #
# Cross-entity nearest neighbour (the pgvector substrate)
# --------------------------------------------------------------------------- #


async def find_similar_profiles(
    db: AsyncSession,
    *,
    org_id: str,
    vector: list[float],
    profile_type: ProfileType | None = None,
    exclude_entity_id: str | None = None,
    limit: int = 5,
) -> list[tuple[BehavioralProfileRow, float]]:
    """Nearest baselines to *vector*, across entities, as ``(profile, distance)``.

    This is the query the JSONB centroid could not express and the reason the
    column moved to pgvector: "which other entities in this org baseline like
    this one?" — the substrate for peer-group comparison and, later, the
    most-similar-normal-example panel.

    Security: strictly scoped to a single ``org_id`` (a cross-tenant baseline
    is never a candidate) and to **active** entities — archived ones are
    excluded so a decommissioned host stops shaping peer comparisons.

    Graceful degradation, mirroring ``memory_service.recall_semantic``: the
    pgvector ORDER BY is emitted only on PostgreSQL (``<=>`` does not exist on
    the SQLite unit-test DB and would raise), and a vector-query failure on
    PostgreSQL (extension missing, dimension mismatch) is scoped to a SAVEPOINT
    so it rolls back only itself. Either way the caller gets the same answer
    from an in-Python cosine scan over the org's candidate profiles — correct,
    just unindexed. The WHERE clause is identical on both paths; only the
    ranking mechanism differs.
    """
    capped = max(1, limit)
    query_vector = _to_centroid_vector(vector)
    if query_vector is None:  # pragma: no cover - defensive; vector is required
        return []

    clauses = [
        BehavioralProfileRow.org_id == org_id,
        BehavioralProfileRow.centroid.is_not(None),
        BehavioralEntityRow.id == BehavioralProfileRow.entity_id,
        BehavioralEntityRow.archived_at.is_(None),
    ]
    if profile_type is not None:
        clauses.append(BehavioralProfileRow.profile_type == profile_type.value)
    if exclude_entity_id is not None:
        clauses.append(BehavioralProfileRow.entity_id != exclude_entity_id)

    async def _fallback(reason: str) -> list[tuple[BehavioralProfileRow, float]]:
        logger.debug("behavioral similarity falling back to in-Python scan: %s", reason)
        stmt = (
            select(BehavioralProfileRow)
            .where(*clauses)
            .order_by(BehavioralProfileRow.window_end.desc())
            .limit(_MAX_FALLBACK_SCAN)
        )
        rows = list((await db.execute(stmt)).scalars().all())
        scored = [
            (
                row,
                behavioral_logic.cosine_distance(query_vector, [float(x) for x in row.centroid]),
            )
            for row in rows
            if row.centroid is not None
        ]
        scored.sort(key=lambda pair: pair[1])
        return scored[:capped]

    if not _is_postgres(db):
        return await _fallback("non-PostgreSQL dialect (pgvector operators unavailable)")

    distance = BehavioralProfileRow.centroid.cosine_distance(query_vector)
    stmt = select(BehavioralProfileRow, distance).where(*clauses).order_by(distance).limit(capped)
    try:
        # SAVEPOINT: on PostgreSQL a failed statement aborts the surrounding
        # transaction, which would take the fallback query — and the caller's
        # own work — down with it.
        async with db.begin_nested():
            result = await db.execute(stmt)
            return [(row, float(dist)) for row, dist in result.all()]
    except Exception:
        logger.warning("behavioral similarity vector query failed; falling back", exc_info=True)
        return await _fallback("vector query error")


# --------------------------------------------------------------------------- #
# Stale-entity sweep + archival (the arq cron calls these)
# --------------------------------------------------------------------------- #


async def stale_entities(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    stale_after: timedelta = timedelta(days=30),
) -> list[BehavioralEntityRow]:
    """Active entities not observed in ``stale_after`` — candidates for archival.

    Already-archived entities are excluded: archival is idempotent, and a
    re-run must not re-report (or re-stamp) what it archived last time.
    """
    cutoff = (now or _utcnow()) - stale_after
    result = await db.execute(
        select(BehavioralEntityRow).where(
            BehavioralEntityRow.last_seen < cutoff,
            BehavioralEntityRow.archived_at.is_(None),
        )
    )
    return list(result.scalars().all())


async def archive_entities(
    db: AsyncSession,
    entities: list[BehavioralEntityRow],
    *,
    now: datetime | None = None,
) -> int:
    """Stamp ``archived_at`` on *entities*; returns how many were newly archived.

    Non-destructive and reversible: nothing is deleted, the entity's baselines
    and outliers stay queryable for audit, and :func:`upsert_entity` clears the
    flag the moment the entity is observed again. Already-archived rows are
    skipped so the sweep is idempotent. Does NOT commit.
    """
    stamp = now or _utcnow()
    archived = 0
    for entity in entities:
        if entity.archived_at is not None:
            continue
        entity.archived_at = stamp
        archived += 1
    if archived:
        await db.flush()
    return archived


async def archive_stale_entities(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    stale_after: timedelta = timedelta(days=30),
) -> tuple[int, int]:
    """Find and archive stale entities. Returns ``(candidates, archived)``.

    The one call the sweep job needs: previously the job could only *count*
    stale entities and log the number, so the active baseline pool grew without
    bound as users left and hosts were decommissioned.
    """
    candidates = await stale_entities(db, now=now, stale_after=stale_after)
    archived = await archive_entities(db, candidates, now=now)
    return len(candidates), archived
