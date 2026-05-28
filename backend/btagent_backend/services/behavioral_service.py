"""Behavioral Hunter service (Phase 6 #114).

Persistence + detection wiring for the baseline-driven hunt mode.
Decisions (cosine distance, frequency-floor comparison, centroid update)
live in the pure logic in :mod:`btagent_shared.hunt.behavioral`; this
module is the side-effectful shell that loads rows, calls that logic, and
writes back.

Per the codebase convention, this service does **not** commit or emit
events — the route layer / agent hook / arq job owns those. Embedding
generation and EDR telemetry ingestion are also out of scope here: the
service accepts pre-computed vectors + pattern keys so it's testable
without a real embedding provider, and the IntentClassifier LLM chain
plugs in via :func:`set_intent` rather than being baked in.
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
    BehavioralEntityRow,
    BehavioralOutlierRow,
    BehavioralProfileRow,
)
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.behavioral")


def _utcnow() -> datetime:
    return datetime.now(UTC)


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

    On hit, bumps ``last_seen`` and merges ``enrichment`` (new keys override).
    On miss, inserts a fresh row.
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
        centroid = [s / len(vectors) for s in sums]

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
    """Build the dependency-free schema for the scorer."""
    from btagent_shared.types.behavioral import BehavioralProfile

    return BehavioralProfile(
        id=row.id,
        org_id=row.org_id,
        entity_id=row.entity_id,
        profile_type=ProfileType(row.profile_type),
        centroid=list(row.centroid) if row.centroid else None,
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
) -> BehavioralOutlierRow | None:
    """Score one event against the entity's latest baseline; persist if outlier.

    Returns the new :class:`BehavioralOutlierRow` (no LLM intent yet —
    populated by :func:`set_intent`), or ``None`` if the event is within
    behavioral bounds. With no baseline yet, returns ``None`` (the scorer
    can't tell signal from "we haven't observed enough" yet, and we'd
    rather under-call than spam).
    """
    profile_row = await _get_latest_profile(db, entity_id=entity.id, profile_type=profile_type)
    if profile_row is None or profile_row.sample_size == 0:
        return None

    profile = _row_to_profile_model(profile_row)
    is_outlier, distance, rank = behavioral_logic.score_outlier(
        profile,
        event_vector,
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
        cosine_distance=distance,
        frequency_rank=rank,
        raw_event_excerpt=raw_event_excerpt[:4096],
        created_at=_utcnow(),
    )
    db.add(row)
    await db.flush()
    return row


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

    profile.frequency_map = behavioral_logic.update_frequency_map(
        dict(profile.frequency_map or {}), outlier.event_id
    )
    profile.pattern_count = len(profile.frequency_map)
    profile.sample_size = profile.sample_size + 1
    profile.updated_at = _utcnow()
    await db.flush()
    return profile


# --------------------------------------------------------------------------- #
# Stale-baseline sweep (the arq cron will call this)
# --------------------------------------------------------------------------- #


async def stale_entities(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    stale_after: timedelta = timedelta(days=30),
) -> list[BehavioralEntityRow]:
    """Entities not observed in ``stale_after`` — flagged for archival."""
    cutoff = (now or _utcnow()) - stale_after
    result = await db.execute(
        select(BehavioralEntityRow).where(BehavioralEntityRow.last_seen < cutoff)
    )
    return list(result.scalars().all())
