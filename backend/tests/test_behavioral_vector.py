"""Tests for the Behavioral Hunter pgvector substrate + live surfacing (#114).

Three slices, one per remaining gap:

* **pgvector centroid** — the model column really is a ``Vector(1536)`` with an
  HNSW cosine index, the ``0063_behavioral_vector`` migration agrees with it,
  and the cross-entity nearest-neighbour query degrades gracefully wherever
  pgvector's operators don't exist (the SQLite unit-test DB) instead of raising.
* **live surfacing** — a detection emits a ``behavioral_outlier_detected``
  event carrying entity/score metadata (never raw telemetry), and emission is
  best-effort: no hub, or a publishing hub that blows up, never breaks a
  detection that is already persisted.
* **stale-entity archival** — the sweep now acts: stale entities are stamped
  ``archived_at``, excluded from subsequent sweeps, excluded from cross-entity
  similarity search, and revived when observed again.

Count-sensitive tests seed a dedicated per-test org (``generate_id("org")``)
rather than ``DEFAULT_ORG_ID`` — the backend suite shares one session-scoped
in-memory SQLite whose committed rows persist across tests.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from btagent_shared.types.behavioral import EntityKind, ProfileType
from btagent_shared.types.events import EventEnvelope, EventType
from btagent_shared.utils.ids import generate_id
from pgvector.sqlalchemy import Vector
from sqlalchemy import select

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_behavioral import (
    CENTROID_DIM,
    BehavioralEntityRow,
    BehavioralProfileRow,
)
from btagent_backend.services import behavioral_service as svc

_MIGRATION = (
    Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0063_behavioral_vector.py"
)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def fresh_org(db_session):
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"Behav Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return oid


def _axis(index: int) -> list[float]:
    """A unit vector on one axis — orthogonal axes are cosine distance 1.0."""
    vec = [0.0] * 8
    vec[index] = 1.0
    return vec


async def _entity_with_baseline(db_session, org_id: str, canonical_id: str, axis: int):
    entity = await svc.upsert_entity(
        db_session, org_id=org_id, kind=EntityKind.HOST, canonical_id=canonical_id
    )
    now = datetime.now(UTC)
    profile = await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[_axis(axis)],
        pattern_keys=[f"{canonical_id}-common"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    return entity, profile


class _RecordingHub:
    """Stands in for ``WebSocketHub`` — records envelopes, no Redis, no egress."""

    def __init__(self) -> None:
        self.published: list[EventEnvelope] = []

    async def publish(self, envelope: EventEnvelope) -> int:
        self.published.append(envelope)
        return 1


class _ExplodingHub:
    async def publish(self, envelope: EventEnvelope) -> int:
        raise RuntimeError("redis is down")


# --------------------------------------------------------------------------- #
# Model <-> migration agreement
# --------------------------------------------------------------------------- #


def test_centroid_column_is_a_pgvector_vector_of_the_shared_dimension():
    column = BehavioralProfileRow.__table__.c.centroid
    assert isinstance(column.type, Vector)
    assert column.type.dim == CENTROID_DIM == 1536
    assert column.nullable is True


def test_model_declares_the_hnsw_cosine_index_like_knowledge_and_memory():
    """Same index shape as ``idx_knowledge_chunks_embedding_hnsw``."""
    from btagent_backend.db.models_knowledge import KnowledgeChunkRow

    # NOTE: conftest strips PG-only indexes off ``Base.metadata`` before
    # create_all, so read the declared args rather than ``__table__.indexes``.
    declared = {
        idx.name: idx
        for idx in BehavioralProfileRow.__table_args__
        if getattr(idx, "name", None) is not None
    }
    idx = declared["idx_behavioral_profiles_centroid_hnsw"]
    pg = idx.dialect_options["postgresql"]
    assert pg["using"] == "hnsw"
    assert pg["with"] == {"m": 16, "ef_construction": 64}
    assert pg["ops"] == {"centroid": "vector_cosine_ops"}

    knowledge = {
        i.name: i for i in KnowledgeChunkRow.__table_args__ if getattr(i, "name", None) is not None
    }["idx_knowledge_chunks_embedding_hnsw"]
    assert pg["with"] == knowledge.dialect_options["postgresql"]["with"]


def test_migration_matches_the_model():
    """The migration creates exactly what the ORM declares (and only 0063)."""
    source = _MIGRATION.read_text()
    assert 'revision: str = "0063_behavioral_vector"' in source
    assert 'down_revision: str | None = "0060_memory_embedding"' in source
    # Revision ids live in a VARCHAR(32) alembic_version column.
    assert len("0063_behavioral_vector") <= 32

    assert f"ADD COLUMN centroid vector({CENTROID_DIM})" in source
    assert "USING hnsw (centroid vector_cosine_ops)" in source
    assert "WITH (m = 16, ef_construction = 64)" in source
    assert "idx_behavioral_profiles_centroid_hnsw" in source
    # Entity lifecycle flag lands in the same revision as the model column.
    assert "archived_at" in source
    assert "idx_behavioral_entities_archived_at" in source
    # Existing centroids are derived data: documented rebuild-on-next-sweep.
    assert "rebuilt on the next" in source


def test_only_one_migration_claims_this_revision_id():
    versions = _MIGRATION.parent
    claiming = [
        path
        for path in versions.glob("*.py")
        if 'revision: str = "0063_behavioral_vector"' in path.read_text()
    ]
    assert claiming == [_MIGRATION]


# --------------------------------------------------------------------------- #
# Centroid width normalisation
# --------------------------------------------------------------------------- #


def test_short_vectors_are_zero_padded_to_the_column_width():
    padded = svc._to_centroid_vector([1.0, 2.0])
    assert padded is not None
    assert len(padded) == CENTROID_DIM
    assert padded[:2] == [1.0, 2.0]
    assert set(padded[2:]) == {0.0}


def test_padding_preserves_cosine_distance():
    """Zero-padding changes neither dot product nor magnitudes."""
    from btagent_shared.hunt import behavioral as logic

    a, b = [1.0, 2.0, 3.0], [3.0, 2.0, 1.0]
    raw = logic.cosine_distance(a, b)
    padded = logic.cosine_distance(
        svc._to_centroid_vector(a),  # type: ignore[arg-type]
        svc._to_centroid_vector(b),  # type: ignore[arg-type]
    )
    assert padded == pytest.approx(raw)


def test_oversized_vectors_are_rejected_rather_than_truncated():
    with pytest.raises(ValueError, match="exceeds the centroid column width"):
        svc._to_centroid_vector([0.1] * (CENTROID_DIM + 1))


async def test_centroid_round_trips_through_the_vector_column(db_session, fresh_org):
    """A committed centroid reads back at full width with its values intact."""
    _, profile = await _entity_with_baseline(db_session, fresh_org, "VEC-RT", axis=0)
    profile_id = profile.id
    await db_session.commit()
    db_session.expire_all()

    stored = await db_session.get(BehavioralProfileRow, profile_id)
    assert stored is not None
    assert len(stored.centroid) == CENTROID_DIM
    assert float(stored.centroid[0]) == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# Cross-entity nearest neighbour — guarded pgvector path + fallback
# --------------------------------------------------------------------------- #


def test_the_postgres_path_really_emits_the_pgvector_operator():
    """The PG ORDER BY compiles to pgvector's ``<=>`` cosine operator."""
    from sqlalchemy.dialects import postgresql

    stmt = select(BehavioralProfileRow.id).order_by(
        BehavioralProfileRow.centroid.cosine_distance([0.0] * CENTROID_DIM)
    )
    assert "<=>" in str(stmt.compile(dialect=postgresql.dialect()))


async def test_similarity_falls_back_on_sqlite(db_session, fresh_org):
    """pgvector operators don't exist on SQLite — degrade, never raise."""
    assert svc._is_postgres(db_session) is False

    await _entity_with_baseline(db_session, fresh_org, "NN-NEAR", axis=0)
    await _entity_with_baseline(db_session, fresh_org, "NN-FAR", axis=3)
    await db_session.flush()

    hits = await svc.find_similar_profiles(db_session, org_id=fresh_org, vector=_axis(0))
    assert len(hits) == 2
    # Ranked by cosine distance: the same-axis baseline first, at distance ~0.
    assert hits[0][1] == pytest.approx(0.0, abs=1e-6)
    assert hits[1][1] == pytest.approx(1.0, abs=1e-6)


async def test_similarity_degrades_when_the_vector_query_errors(
    db_session, fresh_org, monkeypatch, caplog
):
    """Force the pgvector path on SQLite: the failure degrades, not raises."""
    caplog.set_level(logging.WARNING, logger="btagent.services.behavioral")
    await _entity_with_baseline(db_session, fresh_org, "NN-DEGRADE", axis=1)
    await db_session.flush()

    monkeypatch.setattr(svc, "_is_postgres", lambda session: True)
    hits = await svc.find_similar_profiles(db_session, org_id=fresh_org, vector=_axis(1))

    assert "vector query failed" in caplog.text
    assert [h[0].entity_id for h in hits]  # the caller still got an answer
    assert hits[0][1] == pytest.approx(0.0, abs=1e-6)


async def test_similarity_is_org_scoped_and_can_exclude_the_query_entity(db_session):
    """A baseline in another tenant is never a neighbour."""
    org_a, org_b = generate_id("org"), generate_id("org")
    for oid in (org_a, org_b):
        db_session.add(OrganizationRow(id=oid, name=f"Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()

    self_entity, _ = await _entity_with_baseline(db_session, org_a, "NN-SELF", axis=0)
    await _entity_with_baseline(db_session, org_a, "NN-PEER", axis=0)
    await _entity_with_baseline(db_session, org_b, "NN-OTHER-TENANT", axis=0)
    await db_session.flush()

    hits = await svc.find_similar_profiles(
        db_session, org_id=org_a, vector=_axis(0), exclude_entity_id=self_entity.id
    )
    assert [h[0].org_id for h in hits] == [org_a]
    assert self_entity.id not in {h[0].entity_id for h in hits}


async def test_similarity_filters_by_profile_type(db_session, fresh_org):
    entity, _ = await _entity_with_baseline(db_session, fresh_org, "NN-TYPED", axis=0)
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.NETWORK_EGRESS_PROFILE,
        vectors=[_axis(0)],
        pattern_keys=["egress"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    await db_session.flush()

    hits = await svc.find_similar_profiles(
        db_session,
        org_id=fresh_org,
        vector=_axis(0),
        profile_type=ProfileType.NETWORK_EGRESS_PROFILE,
    )
    assert {h[0].profile_type for h in hits} == {ProfileType.NETWORK_EGRESS_PROFILE.value}


# --------------------------------------------------------------------------- #
# Live surfacing — WebSocket event on detection
# --------------------------------------------------------------------------- #


async def test_detect_outlier_emits_a_behavioral_event(db_session, fresh_org, monkeypatch):
    hub = _RecordingHub()
    monkeypatch.setattr("btagent_backend.ws.routes.get_hub_optional", lambda: hub, raising=True)

    entity, _ = await _entity_with_baseline(db_session, fresh_org, "WS-EMIT", axis=0)
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_emit",
        event_vector=_axis(4),  # orthogonal to the baseline -> distance 1.0
        event_pattern_key="winword.exe>powershell.exe",
        raw_event_excerpt="powershell -enc <b64>",
    )
    assert outlier is not None

    assert len(hub.published) == 1
    envelope = hub.published[0]
    assert envelope.type == EventType.BEHAVIORAL_OUTLIER_DETECTED
    assert envelope.data["outlier_id"] == outlier.id
    assert envelope.data["entity_id"] == entity.id
    assert envelope.data["canonical_id"] == "WS-EMIT"
    assert envelope.data["profile_type"] == ProfileType.CMDLINE_EMBEDDING.value
    # org_id drives the hub's per-client org filter + TLP egress gate.
    assert envelope.data["org_id"] == fresh_org
    # The payload is metadata only — raw telemetry never rides the WS.
    assert "raw_event_excerpt" not in envelope.data
    assert "powershell" not in str(envelope.data)


async def test_no_event_when_the_event_is_within_bounds(db_session, fresh_org, monkeypatch):
    hub = _RecordingHub()
    monkeypatch.setattr("btagent_backend.ws.routes.get_hub_optional", lambda: hub, raising=True)

    entity, _ = await _entity_with_baseline(db_session, fresh_org, "WS-QUIET", axis=0)
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_quiet",
        event_vector=_axis(0),  # identical to the centroid
        event_pattern_key="WS-QUIET-common",
    )
    assert outlier is None
    assert hub.published == []


async def test_emission_is_best_effort_and_never_breaks_detection(
    db_session, fresh_org, monkeypatch, caplog
):
    caplog.set_level(logging.WARNING, logger="btagent.services.behavioral")
    monkeypatch.setattr(
        "btagent_backend.ws.routes.get_hub_optional", lambda: _ExplodingHub(), raising=True
    )

    entity, _ = await _entity_with_baseline(db_session, fresh_org, "WS-BOOM", axis=0)
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_boom",
        event_vector=_axis(5),
        event_pattern_key="rare>lineage",
    )
    # The outlier is persisted even though the broadcast blew up.
    assert outlier is not None
    assert await db_session.get(type(outlier), outlier.id) is not None
    assert "event emission failed" in caplog.text


async def test_no_hub_is_a_silent_no_op(db_session, fresh_org, monkeypatch):
    """An arq worker / unit test has no hub — detection must not care."""
    monkeypatch.setattr("btagent_backend.ws.routes.get_hub_optional", lambda: None, raising=True)
    entity, _ = await _entity_with_baseline(db_session, fresh_org, "WS-NOHUB", axis=0)
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_nohub",
        event_vector=_axis(6),
        event_pattern_key="rare>lineage2",
    )
    assert outlier is not None


async def test_emit_event_false_suppresses_the_broadcast(db_session, fresh_org, monkeypatch):
    hub = _RecordingHub()
    monkeypatch.setattr("btagent_backend.ws.routes.get_hub_optional", lambda: hub, raising=True)
    entity, _ = await _entity_with_baseline(db_session, fresh_org, "WS-SILENT", axis=0)
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_silent",
        event_vector=_axis(7),
        event_pattern_key="rare>lineage3",
        emit_event=False,
    )
    assert outlier is not None
    assert hub.published == []


# --------------------------------------------------------------------------- #
# Stale-entity archival
# --------------------------------------------------------------------------- #


async def test_archive_stale_entities_marks_and_excludes(db_session, fresh_org):
    now = datetime.now(UTC)
    fresh = await svc.upsert_entity(
        db_session, org_id=fresh_org, kind=EntityKind.USER, canonical_id="still-here"
    )
    stale = await svc.upsert_entity(
        db_session, org_id=fresh_org, kind=EntityKind.USER, canonical_id="left-the-company"
    )
    stale.last_seen = now - timedelta(days=60)
    await db_session.flush()

    candidates, archived = await svc.archive_stale_entities(
        db_session, now=now, stale_after=timedelta(days=30)
    )
    assert candidates == archived == 1
    assert stale.archived_at is not None
    assert fresh.archived_at is None

    # Excluded from the next sweep — archival is idempotent.
    assert await svc.stale_entities(db_session, now=now, stale_after=timedelta(days=30)) == []
    again = await svc.archive_stale_entities(db_session, now=now, stale_after=timedelta(days=30))
    assert again == (0, 0)


async def test_archived_entities_are_excluded_from_similarity_search(db_session, fresh_org):
    now = datetime.now(UTC)
    live, _ = await _entity_with_baseline(db_session, fresh_org, "ARCH-LIVE", axis=0)
    gone, _ = await _entity_with_baseline(db_session, fresh_org, "ARCH-GONE", axis=0)
    gone.last_seen = now - timedelta(days=90)
    await db_session.flush()

    before = await svc.find_similar_profiles(db_session, org_id=fresh_org, vector=_axis(0))
    assert {h[0].entity_id for h in before} == {live.id, gone.id}

    await svc.archive_stale_entities(db_session, now=now, stale_after=timedelta(days=30))
    after = await svc.find_similar_profiles(db_session, org_id=fresh_org, vector=_axis(0))
    assert {h[0].entity_id for h in after} == {live.id}


async def test_observing_an_archived_entity_revives_it(db_session, fresh_org):
    now = datetime.now(UTC)
    entity = await svc.upsert_entity(
        db_session, org_id=fresh_org, kind=EntityKind.HOST, canonical_id="RETURNED-HOST"
    )
    entity.last_seen = now - timedelta(days=90)
    await db_session.flush()
    await svc.archive_stale_entities(db_session, now=now, stale_after=timedelta(days=30))
    assert entity.archived_at is not None

    revived = await svc.upsert_entity(
        db_session, org_id=fresh_org, kind=EntityKind.HOST, canonical_id="RETURNED-HOST"
    )
    assert revived.id == entity.id
    assert revived.archived_at is None


async def test_the_sweep_job_archives_rather_than_only_counting(db_session, fresh_org, monkeypatch):
    """The arq cron now acts on stale entities instead of logging a count."""
    from contextlib import asynccontextmanager

    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    entity = await svc.upsert_entity(
        db_session, org_id=fresh_org, kind=EntityKind.USER, canonical_id="swept-away"
    )
    entity.last_seen = datetime.now(UTC) - timedelta(days=120)
    await db_session.commit()

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        result = await jobs.behavioral_baseline_sweep({})
    finally:
        get_settings.cache_clear()

    assert result["entities_archived"] >= 1
    assert result["stale_entities"] >= result["entities_archived"]
    assert entity.archived_at is not None


async def test_archival_never_deletes_rows_or_their_baselines(db_session, fresh_org):
    now = datetime.now(UTC)
    entity, profile = await _entity_with_baseline(db_session, fresh_org, "ARCH-AUDIT", axis=2)
    entity.last_seen = now - timedelta(days=90)
    await db_session.flush()

    await svc.archive_stale_entities(db_session, now=now, stale_after=timedelta(days=30))

    rows = (
        (
            await db_session.execute(
                select(BehavioralEntityRow).where(BehavioralEntityRow.org_id == fresh_org)
            )
        )
        .scalars()
        .all()
    )
    assert entity.id in {r.id for r in rows}
    assert await db_session.get(BehavioralProfileRow, profile.id) is not None
