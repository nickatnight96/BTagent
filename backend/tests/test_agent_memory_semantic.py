"""Tests for Agent Memory semantic recall + consolidation (#482, slice 2).

Covers:

* the embedding written on record (deterministic mock embedder) and the
  best-effort guarantee — a missing/failing embedder must NEVER break a write;
* ``recall_semantic``: the SQLite fallback (pgvector's ``<=>`` does not exist
  off PostgreSQL) and the security invariants it must keep on that path — strict
  org scoping and TLP fail-closed filtering;
* consolidation: near-duplicate collapse, ``superseded_at`` stamping, exclusion
  of superseded rows from every recall path, per-org scoping, and the refusal to
  merge across TLP levels;
* the arq sweep job wiring.

Count-sensitive tests seed a dedicated per-test org (``generate_id("org")``)
rather than ``DEFAULT_ORG_ID`` — the backend suite shares one session-scoped
in-memory SQLite whose committed rows persist across tests.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from btagent_shared.types.config import TLP
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_memory import AgentMemoryRow
from btagent_backend.services.embedding_service import (
    EmbeddingService,
    MockEmbeddingService,
)
from btagent_backend.services.memory_service import (
    MemoryService,
    _is_postgres,
    consolidate_all_orgs,
    consolidate_memories,
    content_similarity,
)
from tests.helpers import auth_header

# --------------------------------------------------------------------------- #
# Fixtures / stubs
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def fresh_org(db_session):
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"Sem Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return oid


@pytest_asyncio.fixture()
async def two_orgs(db_session):
    a, b = generate_id("org"), generate_id("org")
    for oid in (a, b):
        db_session.add(OrganizationRow(id=oid, name=f"Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return a, b


class _RaisingEmbedder(EmbeddingService):
    """Stands in for an unconfigured/down provider (e.g. no OpenAI API key)."""

    @property
    def provider_name(self) -> str:
        return "raising"

    async def generate_embeddings(self, texts: list[str]) -> list[list[float]]:
        raise RuntimeError("embeddings provider is not configured")


def _boom_factory() -> EmbeddingService:
    raise RuntimeError("cannot build an embedding provider")


async def _live_rows(session, org_id: str) -> list[AgentMemoryRow]:
    result = await session.execute(
        select(AgentMemoryRow).where(
            AgentMemoryRow.org_id == org_id,
            AgentMemoryRow.superseded_at.is_(None),
        )
    )
    return list(result.scalars().all())


# --------------------------------------------------------------------------- #
# Embedding on record (best-effort)
# --------------------------------------------------------------------------- #


async def test_record_writes_embedding_with_default_mock_embedder(db_session, fresh_org):
    """The default embedder is the deterministic mock — no API key needed."""
    svc = MemoryService()
    assert isinstance(svc._require_embedder(), MockEmbeddingService)

    row = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="10.0.0.5",
        content="Primary domain controller",
    )
    await db_session.commit()
    row_id = row.id

    # Re-read from the DB (not the identity map) so this asserts persistence.
    db_session.expunge_all()
    stored = (
        await db_session.execute(select(AgentMemoryRow).where(AgentMemoryRow.id == row_id))
    ).scalar_one()
    assert stored.embedding is not None
    assert len(stored.embedding) == 1536


async def test_failing_embedder_does_not_break_the_write(db_session, fresh_org):
    """A provider outage records the memory with a NULL embedding, never a 500."""
    svc = MemoryService(embedding_service=_RaisingEmbedder())
    row = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="learning",
        subject="beacon-pattern",
        content="benign scheduled telemetry, not C2",
    )
    await db_session.commit()

    assert row.embedding is None
    # ...and the memory is still fully recallable via the non-vector path.
    recalled = await svc.recall_memories(db_session, fresh_org, subject="beacon-pattern")
    assert len(recalled) == 1
    assert recalled[0].content == "benign scheduled telemetry, not C2"


async def test_embedding_factory_that_raises_does_not_break_the_write(db_session, fresh_org):
    """Even building the embedder can fail — the write still lands."""
    svc = MemoryService(embedding_factory=_boom_factory)
    row = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="observation",
        subject="host-factory-boom",
        content="observed once",
    )
    await db_session.commit()
    assert row.embedding is None


# --------------------------------------------------------------------------- #
# recall_semantic — SQLite fallback + preserved security invariants
# --------------------------------------------------------------------------- #


async def test_semantic_recall_falls_back_cleanly_on_sqlite(db_session, fresh_org):
    """pgvector operators don't exist on SQLite — degrade, never raise."""
    assert _is_postgres(db_session) is False

    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="198.51.100.7",
        content="scanner noise from a partner range",
    )
    await db_session.commit()

    rows = await svc.recall_semantic(db_session, fresh_org, "who is scanning us")
    assert [r.subject for r in rows] == ["198.51.100.7"]


def test_vector_ordering_compiles_to_the_pgvector_operator():
    """The PostgreSQL path is real: the ORDER BY emits pgvector's ``<=>``."""
    from sqlalchemy.dialects import postgresql

    stmt = select(AgentMemoryRow.id).order_by(
        AgentMemoryRow.embedding.cosine_distance([0.0] * 1536)
    )
    sql = str(stmt.compile(dialect=postgresql.dialect()))
    assert "<=>" in sql


async def test_semantic_recall_degrades_when_the_vector_query_errors(
    db_session, fresh_org, monkeypatch, caplog
):
    """Force the vector path on SQLite: the ``<=>`` failure must degrade, not raise."""
    import btagent_backend.services.memory_service as mod

    caplog.set_level(logging.WARNING, logger="btagent.services.memory")
    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="degrade-host",
        content="a fact that must still come back",
    )
    await db_session.commit()

    monkeypatch.setattr(mod, "_is_postgres", lambda session: True)
    rows = await svc.recall_semantic(db_session, fresh_org, "a fact")
    # The vector statement really was attempted (and really did fail here) —
    # the caller still gets the recency-ranked answer.
    assert "Semantic memory recall failed" in caplog.text
    assert [r.subject for r in rows] == ["degrade-host"]


async def test_semantic_recall_empty_query_falls_back(db_session, fresh_org):
    svc = MemoryService()
    await svc.record_memory(
        db_session, org_id=fresh_org, kind="decision", subject="inv_x", content="closed benign"
    )
    await db_session.commit()

    rows = await svc.recall_semantic(db_session, fresh_org, "   ")
    assert len(rows) == 1


async def test_semantic_recall_withholds_red_from_green_clearance(db_session, fresh_org):
    """TLP fail-closed must hold on the semantic path too."""
    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="green-host-sem",
        content="green fact",
        tlp_level=TLP.GREEN,
    )
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="red-host-sem",
        content="restricted fact",
        tlp_level=TLP.RED,
    )
    await db_session.commit()

    green = await svc.recall_semantic(db_session, fresh_org, "host fact", caller_tlp=TLP.GREEN)
    subjects = {r.subject for r in green}
    assert "green-host-sem" in subjects
    assert "red-host-sem" not in subjects

    red = await svc.recall_semantic(db_session, fresh_org, "host fact", caller_tlp=TLP.RED)
    assert {"green-host-sem", "red-host-sem"} <= {r.subject for r in red}


async def test_semantic_recall_unknown_tlp_value_fails_closed(db_session, fresh_org):
    """A garbage stored ``tlp_level`` matches no allowed value — never returned."""
    db_session.add(
        AgentMemoryRow(
            id=generate_id("mem"),
            org_id=fresh_org,
            kind="entity_note",
            subject="garbage-tlp-host",
            content="should never surface",
            source="",
            tlp_level="not-a-tlp",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    rows = await MemoryService().recall_semantic(
        db_session, fresh_org, "anything", caller_tlp=TLP.RED
    )
    assert "garbage-tlp-host" not in {r.subject for r in rows}


async def test_semantic_recall_is_org_scoped(db_session, two_orgs):
    org_a, org_b = two_orgs
    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=org_a,
        kind="entity_note",
        subject="tenant-a-only",
        content="org A private fact about a domain controller",
    )
    await db_session.commit()

    assert await svc.recall_semantic(db_session, org_b, "domain controller") == []
    a_rows = await svc.recall_semantic(db_session, org_a, "domain controller")
    assert [r.subject for r in a_rows] == ["tenant-a-only"]


# --------------------------------------------------------------------------- #
# Consolidation
# --------------------------------------------------------------------------- #


def test_content_similarity_bounds():
    assert content_similarity("same fact", "Same  fact!") == 1.0
    assert content_similarity("", "x") == 0.0
    assert content_similarity("primary domain controller", "exfiltrated 4GB to Russia") < 0.5


async def _seed_near_duplicates(session, org_id: str) -> None:
    """Three near-identical facts about one entity, recorded under 3 kinds."""
    svc = MemoryService()
    await svc.record_memory(
        session,
        org_id=org_id,
        kind="entity_note",
        subject="203.0.113.9",
        content="ip observed beaconing in investigation inv_1; disposition=closed",
        source="inv_1",
        confidence=0.4,
    )
    await svc.record_memory(
        session,
        org_id=org_id,
        kind="observation",
        subject="203.0.113.9",
        content="ip observed beaconing in investigation inv_2; disposition=closed",
        source="inv_2",
        confidence=0.9,
    )
    await svc.record_memory(
        session,
        org_id=org_id,
        kind="decision",
        subject="203.0.113.9",
        content="ip observed beaconing in investigation inv_3; disposition=closed",
        source="inv_3",
        confidence=0.6,
    )
    await session.commit()


async def test_consolidation_collapses_duplicates_and_marks_superseded(db_session, fresh_org):
    await _seed_near_duplicates(db_session, fresh_org)
    assert len(await _live_rows(db_session, fresh_org)) == 3

    result = await consolidate_memories(db_session, fresh_org)
    await db_session.commit()

    assert result.scanned == 3
    assert result.groups == 1
    assert result.superseded == 2

    live = await _live_rows(db_session, fresh_org)
    assert len(live) == 1
    survivor = live[0]
    # Highest confidence wins, and absorbs the cluster's best confidence...
    assert survivor.kind == "observation"
    assert survivor.confidence == 0.9
    # ...and the union of the collapsed rows' sources.
    assert set(survivor.source.split(",")) == {"inv_1", "inv_2", "inv_3"}

    # The losers are retained (auditable) but stamped.
    all_rows = (
        (await db_session.execute(select(AgentMemoryRow).where(AgentMemoryRow.org_id == fresh_org)))
        .scalars()
        .all()
    )
    assert len(all_rows) == 3
    assert sum(1 for r in all_rows if r.superseded_at is not None) == 2


async def test_superseded_rows_are_excluded_from_recall(db_session, fresh_org):
    await _seed_near_duplicates(db_session, fresh_org)
    await consolidate_memories(db_session, fresh_org)
    await db_session.commit()

    svc = MemoryService()
    recency = await svc.recall_memories(db_session, fresh_org, subject="203.0.113.9")
    assert len(recency) == 1
    assert recency[0].kind == "observation"

    # The semantic path (SQLite → recency fallback) must exclude them too.
    semantic = await svc.recall_semantic(db_session, fresh_org, "beaconing ip")
    assert [r.id for r in semantic] == [recency[0].id]

    # Explicit opt-in still surfaces them for audit.
    audited = await svc.recall_memories(
        db_session, fresh_org, subject="203.0.113.9", include_superseded=True
    )
    assert len(audited) == 3


async def test_consolidation_keeps_distinct_facts(db_session, fresh_org):
    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="10.10.10.10",
        content="primary domain controller for the corp forest",
    )
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="observation",
        subject="10.10.10.10",
        content="exfiltrated 4GB over DNS to an unattributed external host",
    )
    await db_session.commit()

    result = await consolidate_memories(db_session, fresh_org)
    await db_session.commit()

    assert result.superseded == 0
    assert len(await _live_rows(db_session, fresh_org)) == 2


async def test_consolidation_never_merges_across_tlp_levels(db_session, fresh_org):
    """Collapsing a RED fact into a GREEN survivor would leak or withhold."""
    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="tlp-split-host",
        content="host implicated in the campaign; disposition=closed",
        tlp_level=TLP.GREEN,
    )
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="observation",
        subject="tlp-split-host",
        content="host implicated in the campaign; disposition=closed",
        tlp_level=TLP.RED,
    )
    await db_session.commit()

    result = await consolidate_memories(db_session, fresh_org)
    await db_session.commit()

    assert result.superseded == 0
    live = await _live_rows(db_session, fresh_org)
    assert {r.tlp_level for r in live} == {"green", "red"}


async def test_consolidation_is_org_scoped(db_session, two_orgs):
    org_a, org_b = two_orgs
    await _seed_near_duplicates(db_session, org_a)
    await _seed_near_duplicates(db_session, org_b)

    result = await consolidate_memories(db_session, org_a)
    await db_session.commit()

    assert result.scanned == 3  # org B's rows were never even read
    assert len(await _live_rows(db_session, org_a)) == 1
    # Org B is untouched by org A's consolidation.
    assert len(await _live_rows(db_session, org_b)) == 3


async def test_consolidate_all_orgs_walks_every_tenant(db_session, two_orgs):
    org_a, org_b = two_orgs
    await _seed_near_duplicates(db_session, org_a)
    await _seed_near_duplicates(db_session, org_b)

    await consolidate_all_orgs(db_session)
    await db_session.commit()

    assert len(await _live_rows(db_session, org_a)) == 1
    assert len(await _live_rows(db_session, org_b)) == 1


async def test_re_recording_revives_a_superseded_row(db_session, fresh_org):
    """The (org, kind, subject) upsert must clear a stale supersede stamp."""
    await _seed_near_duplicates(db_session, fresh_org)
    await consolidate_memories(db_session, fresh_org)
    await db_session.commit()

    svc = MemoryService()
    revived = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",  # the row consolidation superseded
        subject="203.0.113.9",
        content="re-observed with fresh evidence",
        source="inv_9",
        confidence=0.95,
    )
    await db_session.commit()

    assert revived.superseded_at is None
    recalled = await svc.recall_memories(db_session, fresh_org, subject="203.0.113.9")
    assert {r.kind for r in recalled} == {"entity_note", "observation"}


async def test_consolidation_prefers_most_recent_on_confidence_tie(db_session, fresh_org):
    svc = MemoryService()
    older = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="tie-host",
        content="tie host observed beaconing during investigation one",
        confidence=0.5,
    )
    newer = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="observation",
        subject="tie-host",
        content="tie host observed beaconing during investigation two",
        confidence=0.5,
    )
    older.updated_at = datetime.now(UTC) - timedelta(days=3)
    newer.updated_at = datetime.now(UTC)
    await db_session.commit()

    await consolidate_memories(db_session, fresh_org)
    await db_session.commit()

    live = await _live_rows(db_session, fresh_org)
    assert [r.id for r in live] == [newer.id]


# --------------------------------------------------------------------------- #
# Scheduled job wiring
# --------------------------------------------------------------------------- #


async def test_memory_consolidation_sweep_job(db_session, fresh_org, monkeypatch):
    """The arq shell delegates to the service and commits (mirrors the hunt jobs)."""
    from contextlib import asynccontextmanager

    from btagent_backend.scheduler import jobs

    @asynccontextmanager
    async def _session_cm():
        # The job opens its own session via ``async_session_factory``; point
        # that at the test session, as the other job tests do.
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)

    await _seed_near_duplicates(db_session, fresh_org)

    counts = await jobs.memory_consolidation_sweep({})
    assert counts["superseded"] >= 2

    assert len(await _live_rows(db_session, fresh_org)) == 1


def test_sweep_is_registered_on_the_worker():
    from btagent_backend.scheduler.jobs import memory_consolidation_sweep
    from btagent_backend.scheduler.worker import WorkerSettings

    assert memory_consolidation_sweep in WorkerSettings.functions
    assert any(
        getattr(job, "coroutine", None) is memory_consolidation_sweep
        or getattr(job, "name", "") == "memory_consolidation_sweep"
        for job in WorkerSettings.cron_jobs
    )


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


async def test_api_semantic_recall_query_param(client, admin_token, analyst_token):
    subject = f"sem-host-{generate_id('mem')}"
    resp = await client.post(
        "/api/v1/memory",
        headers=auth_header(admin_token),
        json={
            "kind": "learning",
            "subject": subject,
            "content": "credential stuffing against the VPN portal was blocked",
        },
    )
    assert resp.status_code == 201, resp.text

    got = await client.get(
        f"/api/v1/memory?query=vpn%20credential%20stuffing&subject={subject}",
        headers=auth_header(analyst_token),
    )
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["mode"] == "semantic"
    assert body["total"] == 1
    assert body["items"][0]["subject"] == subject


async def test_api_recall_without_query_stays_recency(client, analyst_token):
    got = await client.get("/api/v1/memory", headers=auth_header(analyst_token))
    assert got.status_code == 200
    assert got.json()["mode"] == "recency"
