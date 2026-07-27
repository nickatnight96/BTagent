"""Telemetry → vector ingestion bridge for the Behavioral Hunter (#114 Phase A last-mile).

The persistence layer (:mod:`behavioral_service`) intentionally takes
*pre-computed* vectors + pattern keys so it stays testable without an
embedding provider. That left a gap: nothing outside the tests actually
turned raw EDR ``cmdline`` telemetry into those vectors. This module is the
missing seam — it embeds cmdline text via :mod:`embedding_service` and feeds
:func:`behavioral_service.build_baseline` / :func:`behavioral_service.detect_outlier`.

Three entry points, all thin shells over ``embedding_service`` +
``behavioral_service`` (none of them commit — the job / route / consumer that
called in owns the single commit, per the service convention):

* :func:`build_baseline_from_events` — embed a batch of an entity's recent
  cmdlines and fold them into a fresh baseline window (used by the scheduler's
  baseline-rebuild half).
* :func:`score_event` — embed one incoming event's cmdline and score it
  against the entity's latest baseline (persisting an outlier if anomalous).
* :func:`consume_process_event` — the OCSF process-activity consumer: parse an
  OCSF (or EDR-shaped) process event, upsert its entity, and live-score it.
  This is the non-test caller of ``detect_outlier``.

Design notes:

1. **Injectable providers.** ``embedding_service`` and the EDR connector are
   parameters (defaulting to the configured concrete ones) so tests pass the
   deterministic ``MockEmbeddingService`` / a stub connector with no network.
2. **Empty cmdlines don't poison the centroid.** Only non-blank cmdlines are
   embedded; the process-lineage pattern key is derived independently, so a
   telemetry row with a lineage but no captured cmdline still contributes its
   pattern.
3. **Pattern key = process lineage.** ``parent_image>child_image`` (basenames,
   lowercased) — the Living-off-the-Land tell is an anomalous parent/child
   process chain (winword.exe → powershell.exe), which the frequency map
   scores independently of the cmdline embedding.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from btagent_shared.types.behavioral import EntityKind, ProfileType
from btagent_shared.utils.ids import generate_id
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import get_settings
from btagent_backend.db.models_behavioral import (
    BehavioralEntityRow,
    BehavioralOutlierRow,
    BehavioralProfileRow,
)
from btagent_backend.services import behavioral_service
from btagent_backend.services.embedding_service import EmbeddingService, get_embedding_service

logger = logging.getLogger("btagent.services.behavioral_ingest")


# --------------------------------------------------------------------------- #
# Normalized telemetry shape
# --------------------------------------------------------------------------- #


class ProcessEvent(BaseModel):
    """A single process-creation telemetry record, normalized across sources.

    Both the EDR baseline pull (CrowdStrike ProcessRollup2) and the live OCSF
    process-activity consumer parse into this shape before it reaches the
    embedding bridge.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default="")
    # The subject the event is attributed to (host name / user upn / ip).
    entity_canonical_id: str = Field(default="")
    entity_kind: EntityKind = EntityKind.HOST
    cmdline: str = Field(default="")
    process_name: str = Field(default="")
    parent_name: str = Field(default="")
    raw_excerpt: str = Field(default="")


def _basename(image: str) -> str:
    """Last path segment of a Windows/Unix image path, lowercased."""
    if not image:
        return ""
    # Split on both separators so ``C:\\Windows\\...\\powershell.exe`` and
    # ``/usr/bin/python`` both reduce to the executable name.
    tail = image.replace("\\", "/").rsplit("/", 1)[-1]
    return tail.strip().lower()


def process_pattern_key(parent_image: str, child_image: str) -> str:
    """Build the ``parent>child`` process-lineage key the scorer matches on.

    Basenames only, lowercased, so ``C:\\...\\winword.exe`` and ``winword.exe``
    collapse to the same lineage. Returns ``""`` when neither side is known
    (the caller then relies on the cmdline embedding alone).
    """
    parent = _basename(parent_image)
    child = _basename(child_image)
    if not parent and not child:
        return ""
    return f"{parent}>{child}"


def _excerpt_for(event: ProcessEvent) -> str:
    """A human-readable one-liner for the outlier's ``raw_event_excerpt``."""
    if event.raw_excerpt:
        return event.raw_excerpt
    lineage = process_pattern_key(event.parent_name, event.process_name)
    body = event.cmdline or event.process_name
    return f"{lineage}: {body}" if lineage else body


def _resolve_embedder(embedding_service: EmbeddingService | None) -> EmbeddingService:
    return (
        embedding_service
        if embedding_service is not None
        else get_embedding_service(get_settings())
    )


# --------------------------------------------------------------------------- #
# Baseline build (batch)
# --------------------------------------------------------------------------- #


async def build_baseline_from_events(
    db: AsyncSession,
    *,
    entity: BehavioralEntityRow,
    events: list[ProcessEvent],
    window_start: datetime,
    window_end: datetime,
    profile_type: ProfileType = ProfileType.CMDLINE_EMBEDDING,
    embedding_service: EmbeddingService | None = None,
) -> BehavioralProfileRow:
    """Embed a batch of an entity's cmdlines and build a fresh baseline window.

    The cmdline embeddings become the centroid; the ``parent>child`` lineage
    keys become the frequency map. Does NOT commit.
    """
    embedder = _resolve_embedder(embedding_service)

    cmdlines = [e.cmdline for e in events if e.cmdline.strip()]
    vectors = await embedder.generate_embeddings(cmdlines) if cmdlines else []

    pattern_keys = [
        key for e in events if (key := process_pattern_key(e.parent_name, e.process_name))
    ]

    return await behavioral_service.build_baseline(
        db,
        entity=entity,
        profile_type=profile_type,
        vectors=vectors,
        pattern_keys=pattern_keys,
        window_start=window_start,
        window_end=window_end,
    )


# --------------------------------------------------------------------------- #
# Live scoring (single event)
# --------------------------------------------------------------------------- #


async def score_event(
    db: AsyncSession,
    *,
    entity: BehavioralEntityRow,
    event: ProcessEvent,
    profile_type: ProfileType = ProfileType.CMDLINE_EMBEDDING,
    embedding_service: EmbeddingService | None = None,
    distance_threshold: float = 0.35,
    frequency_floor: int = 1,
) -> BehavioralOutlierRow | None:
    """Embed one event's cmdline and score it against the entity's baseline.

    Returns the persisted :class:`BehavioralOutlierRow` when anomalous, else
    ``None`` (including when the entity has no baseline yet). Does NOT commit.
    """
    embedder = _resolve_embedder(embedding_service)

    event_vector: list[float] | None = None
    if event.cmdline.strip():
        vectors = await embedder.generate_embeddings([event.cmdline])
        event_vector = vectors[0] if vectors else None

    pattern_key = process_pattern_key(event.parent_name, event.process_name) or None
    event_id = event.event_id or generate_id("evt")

    return await behavioral_service.detect_outlier(
        db,
        entity=entity,
        profile_type=profile_type,
        event_id=event_id,
        event_vector=event_vector,
        event_pattern_key=pattern_key,
        raw_event_excerpt=_excerpt_for(event),
        distance_threshold=distance_threshold,
        frequency_floor=frequency_floor,
    )


# --------------------------------------------------------------------------- #
# OCSF process-activity consumer (task C)
# --------------------------------------------------------------------------- #


def _dig(obj: Any, *path: str) -> Any:
    """Walk a nested-dict path, returning ``None`` on any missing/typeless hop."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def process_event_from_ocsf(ocsf: dict[str, Any]) -> ProcessEvent | None:
    """Parse an OCSF Process Activity (class_uid 1007) event into a ProcessEvent.

    Tolerant of partial payloads: the ``process`` object supplies the child
    process + cmdline, ``actor.process`` the parent, ``device`` the host, and
    ``actor.user`` the user. Attribution prefers the host; falls back to the
    user when no hostname is present. Returns ``None`` when neither a host nor
    a user can be resolved (nothing to key a profile on).
    """
    if not isinstance(ocsf, dict):
        return None

    cmdline = _dig(ocsf, "process", "cmd_line") or _dig(ocsf, "process", "cmdline") or ""
    process_name = _dig(ocsf, "process", "name") or _dig(ocsf, "process", "file", "name") or ""
    parent_name = (
        _dig(ocsf, "actor", "process", "name")
        or _dig(ocsf, "actor", "process", "file", "name")
        or ""
    )
    hostname = _dig(ocsf, "device", "hostname") or _dig(ocsf, "device", "name") or ""
    user = _dig(ocsf, "actor", "user", "name") or ""
    event_id = ocsf.get("uid") or _dig(ocsf, "metadata", "uid") or generate_id("evt")

    if hostname:
        canonical, kind = str(hostname), EntityKind.HOST
    elif user:
        canonical, kind = str(user), EntityKind.USER
    else:
        return None

    return ProcessEvent(
        event_id=str(event_id),
        entity_canonical_id=canonical,
        entity_kind=kind,
        cmdline=str(cmdline),
        process_name=str(process_name),
        parent_name=str(parent_name),
    )


async def consume_process_event(
    db: AsyncSession,
    *,
    org_id: str,
    ocsf_event: dict[str, Any],
    profile_type: ProfileType = ProfileType.CMDLINE_EMBEDDING,
    embedding_service: EmbeddingService | None = None,
    distance_threshold: float = 0.35,
    frequency_floor: int = 1,
) -> BehavioralOutlierRow | None:
    """Live-score one incoming OCSF process-activity event via the detector.

    The consumer half of the Behavioral Hunter: parse the OCSF event, upsert
    its entity (bumping ``last_seen``), and score its cmdline against the
    entity's latest baseline. Returns the persisted outlier or ``None`` (no
    entity resolvable, no baseline yet, or within behavioral bounds). Does NOT
    commit — the caller (WS ingest loop / batch job) owns that.
    """
    event = process_event_from_ocsf(ocsf_event)
    if event is None:
        logger.debug("skipping OCSF event with no resolvable entity")
        return None

    entity = await behavioral_service.upsert_entity(
        db,
        org_id=org_id,
        kind=event.entity_kind,
        canonical_id=event.entity_canonical_id,
    )
    return await score_event(
        db,
        entity=entity,
        event=event,
        profile_type=profile_type,
        embedding_service=embedding_service,
        distance_threshold=distance_threshold,
        frequency_floor=frequency_floor,
    )


# --------------------------------------------------------------------------- #
# EDR baseline rebuild (task B) — mock-first CrowdStrike telemetry pull
# --------------------------------------------------------------------------- #


def _edr_event_to_process_event(raw: dict[str, Any]) -> ProcessEvent | None:
    """Map a CrowdStrike ProcessRollup2 telemetry row into a ProcessEvent."""
    hostname = raw.get("hostname") or ""
    if not hostname:
        return None
    return ProcessEvent(
        event_id=str(raw.get("event_id") or generate_id("evt")),
        entity_canonical_id=str(hostname),
        entity_kind=EntityKind.HOST,
        cmdline=str(raw.get("cmdline") or ""),
        process_name=str(raw.get("filename") or ""),
        parent_name=str(raw.get("parent_image_filename") or ""),
    )


async def _default_edr_connector() -> Any:
    """Instantiate the mock-first CrowdStrike MCP server (lazy agents import)."""
    from btagent_agents.mcp.servers.crowdstrike_mcp import CrowdStrikeMCPServer

    return CrowdStrikeMCPServer()


async def rebuild_baselines_from_edr(
    db: AsyncSession,
    *,
    org_id: str,
    lookback_days: int = 30,
    edr: Any | None = None,
    embedding_service: EmbeddingService | None = None,
    profile_type: ProfileType = ProfileType.CMDLINE_EMBEDDING,
    now: datetime | None = None,
) -> dict[str, int]:
    """Pull last-``lookback_days`` EDR process telemetry and rebuild baselines.

    Groups the CrowdStrike ProcessRollup2 telemetry by host, upserts each host
    entity, and builds one fresh baseline window per host via the embedding
    bridge. Returns ``{"entities": N, "baselines_built": M, "events": K}``.
    Does NOT commit — the scheduler job owns the single commit.
    """
    connector = edr if edr is not None else await _default_edr_connector()
    window_end = now or datetime.now(UTC)
    window_start = window_end - timedelta(days=lookback_days)

    payload = await connector.cs_process_telemetry(lookback_days=lookback_days)
    raw_events = payload.get("events", []) if isinstance(payload, dict) else []

    # Group telemetry by host entity.
    per_host: dict[str, list[ProcessEvent]] = {}
    for raw in raw_events:
        event = _edr_event_to_process_event(raw)
        if event is None:
            continue
        per_host.setdefault(event.entity_canonical_id, []).append(event)

    baselines_built = 0
    total_events = 0
    for hostname, events in per_host.items():
        total_events += len(events)
        entity = await behavioral_service.upsert_entity(
            db, org_id=org_id, kind=EntityKind.HOST, canonical_id=hostname
        )
        await build_baseline_from_events(
            db,
            entity=entity,
            events=events,
            window_start=window_start,
            window_end=window_end,
            profile_type=profile_type,
            embedding_service=embedding_service,
        )
        baselines_built += 1

    logger.info(
        "rebuild_baselines_from_edr: org=%s entities=%d baselines=%d events=%d",
        org_id,
        len(per_host),
        baselines_built,
        total_events,
    )
    return {
        "entities": len(per_host),
        "baselines_built": baselines_built,
        "events": total_events,
    }


__all__ = [
    "ProcessEvent",
    "build_baseline_from_events",
    "consume_process_event",
    "process_event_from_ocsf",
    "process_pattern_key",
    "rebuild_baselines_from_edr",
    "score_event",
]
