"""Cross-tenant org-scoping tests for the Knowledge base / RAG store (GH #386).

Before this fix, ``knowledge_documents`` / ``knowledge_chunks`` had no
``org_id`` and every ``/knowledge`` endpoint was gated by RBAC only — org B
could query/read/delete org A's knowledge docs, and auto-indexing wrote one
org's case data into the shared store.

These tests pin the fix at two levels:

* API level (full route -> service -> DB): a doc ingested by org A is invisible
  to an org-B caller (even an org-B admin) — get/delete return 404 (never 403,
  never 200) and it is absent from org B's listing, while org A sees it.
* Service level (``KnowledgeService`` directly): every read/write is scoped by
  ``org_id`` — ingest stamps the org onto the doc and all chunks, and
  get/list/chunk-count/delete/hybrid_search never cross the tenant boundary.

Each test provisions two *unique* organizations so committed API data can't
leak between tests (the in-memory SQLite schema persists for the session).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import InvestigationRow, OrganizationRow, UserRow
from btagent_backend.db.models_knowledge import KnowledgeChunkRow
from btagent_backend.services.embedding_service import MockEmbeddingService
from btagent_backend.services.knowledge_service import KnowledgeService

_PASSWORD = "Test-P@ss-386!"


@pytest.fixture()
def mock_embeddings(monkeypatch):
    """Force the ``/knowledge`` route to use the deterministic mock embedder.

    ``_get_knowledge_service`` otherwise builds a live OpenAI embedder from
    settings; with no API key configured in the test env it emits an empty
    ``Authorization: Bearer`` header and the outbound call fails. Patching the
    factory keeps these tests focused on org scoping, not embedding transport.
    """
    import btagent_backend.api.v1.knowledge as knowledge_api

    monkeypatch.setattr(
        knowledge_api,
        "_get_knowledge_service",
        lambda: KnowledgeService(embedding_service=MockEmbeddingService()),
    )


# --------------------------------------------------------------------------- #
# Scaffolding
# --------------------------------------------------------------------------- #


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _token(user: UserRow) -> str:
    return create_token_pair(user.id, user.username, user.role, org_id=user.org_id).access_token


async def _ensure_org(db: AsyncSession, org_id: str) -> None:
    existing = await db.get(OrganizationRow, org_id)
    if existing is None:
        db.add(
            OrganizationRow(
                id=org_id,
                name=org_id.replace("_", "-"),
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()


async def _make_user(
    db: AsyncSession,
    *,
    org_id: str,
    role: str = "admin",
    label: str = "user",
) -> UserRow:
    suffix = generate_id("usr").split("_", 1)[1]
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"{label}_{suffix}",
        email=f"{label}_{suffix}@btagent.test",
        password_hash=hash_password(_PASSWORD),
        role=role,
        created_at=datetime.now(UTC),
    )
    db.add(user)
    await db.commit()
    return user


@pytest_asyncio.fixture()
async def two_orgs(db_session: AsyncSession) -> dict:
    """Two fresh, unique organizations, each with an admin (+ an org-B analyst).

    ``admin`` covers every knowledge permission (query/ingest/delete) so a
    single caller can exercise the full surface; the extra org-B analyst proves
    a *lower*-privilege cross-org caller is blocked the same way.
    """
    org_a = generate_id("org")
    org_b = generate_id("org")
    await _ensure_org(db_session, org_a)
    await _ensure_org(db_session, org_b)
    return {
        "org_a": org_a,
        "org_b": org_b,
        "admin_a": await _make_user(db_session, org_id=org_a, role="admin", label="admin_a"),
        "admin_b": await _make_user(db_session, org_id=org_b, role="admin", label="admin_b"),
        "analyst_b": await _make_user(db_session, org_id=org_b, role="analyst", label="analyst_b"),
    }


# --------------------------------------------------------------------------- #
# API-level cross-tenant isolation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_cross_org_document_get_delete_list_isolation(
    client: AsyncClient, two_orgs: dict, mock_embeddings
):
    """Org A ingests a doc; org B (admin) can't see, get, delete, or list it."""
    tok_a = _token(two_orgs["admin_a"])
    tok_b = _token(two_orgs["admin_b"])

    ingest = await client.post(
        "/api/v1/knowledge/ingest",
        headers=_auth(tok_a),
        json={
            "title": "Org A Confidential Runbook",
            "content": "APT-4242 lateral movement via PsExec. Case ABC-123.",
            "source_type": "runbook",
        },
    )
    assert ingest.status_code == 201, ingest.text
    doc_id = ingest.json()["id"]

    # Org B admin GET -> 404 (existence oracle: never 403, never 200).
    r = await client.get(f"/api/v1/knowledge/documents/{doc_id}", headers=_auth(tok_b))
    assert r.status_code == 404

    # Org B admin DELETE -> 404 (and must not actually remove the doc).
    r = await client.delete(f"/api/v1/knowledge/documents/{doc_id}", headers=_auth(tok_b))
    assert r.status_code == 404

    # Org B listing excludes the doc.
    r = await client.get("/api/v1/knowledge/documents", headers=_auth(tok_b))
    assert r.status_code == 200
    assert doc_id not in {d["id"] for d in r.json()["items"]}

    # Org A owner still sees it (proves org B's DELETE didn't touch it).
    r = await client.get(f"/api/v1/knowledge/documents/{doc_id}", headers=_auth(tok_a))
    assert r.status_code == 200
    assert r.json()["id"] == doc_id

    # Org A listing includes it.
    r = await client.get("/api/v1/knowledge/documents", headers=_auth(tok_a))
    assert doc_id in {d["id"] for d in r.json()["items"]}


@pytest.mark.asyncio
async def test_org_owner_can_delete_own_document(
    client: AsyncClient, two_orgs: dict, mock_embeddings
):
    """Positive control: the owning org can delete its own doc (204, then 404)."""
    tok_a = _token(two_orgs["admin_a"])

    ingest = await client.post(
        "/api/v1/knowledge/ingest",
        headers=_auth(tok_a),
        json={
            "title": "Deletable Doc",
            "content": "ephemeral content for deletion test",
            "source_type": "runbook",
        },
    )
    assert ingest.status_code == 201, ingest.text
    doc_id = ingest.json()["id"]

    r = await client.delete(f"/api/v1/knowledge/documents/{doc_id}", headers=_auth(tok_a))
    assert r.status_code == 204

    r = await client.get(f"/api/v1/knowledge/documents/{doc_id}", headers=_auth(tok_a))
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Service-level org scoping
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_ingest_stamps_org_id_on_document_and_chunks(
    db_session: AsyncSession, two_orgs: dict
):
    svc = KnowledgeService()
    doc = await svc.ingest_document(
        db_session,
        title="Chunked doc",
        content="sensitive content that should be chunked. " * 40,
        source_type="runbook",
        org_id=two_orgs["org_a"],
    )
    assert doc.org_id == two_orgs["org_a"]

    chunk_rows = (
        (
            await db_session.execute(
                select(KnowledgeChunkRow).where(KnowledgeChunkRow.document_id == doc.id)
            )
        )
        .scalars()
        .all()
    )
    assert chunk_rows, "expected at least one chunk"
    assert all(c.org_id == two_orgs["org_a"] for c in chunk_rows)


@pytest.mark.asyncio
async def test_get_delete_chunk_count_are_org_scoped(db_session: AsyncSession, two_orgs: dict):
    svc = KnowledgeService()
    doc = await svc.ingest_document(
        db_session,
        title="Org A doc",
        content="org A only content " * 40,
        source_type="runbook",
        org_id=two_orgs["org_a"],
    )
    await db_session.flush()

    # Wrong org: invisible / untouchable.
    assert await svc.get_document(db_session, doc.id, org_id=two_orgs["org_b"]) is None
    assert await svc.get_document_chunk_count(db_session, doc.id, org_id=two_orgs["org_b"]) == 0
    assert await svc.delete_document(db_session, doc.id, org_id=two_orgs["org_b"]) is False

    # Right org: still present after the cross-org delete attempt.
    assert await svc.get_document(db_session, doc.id, org_id=two_orgs["org_a"]) is not None
    assert await svc.get_document_chunk_count(db_session, doc.id, org_id=two_orgs["org_a"]) > 0

    # Owning org can delete.
    assert await svc.delete_document(db_session, doc.id, org_id=two_orgs["org_a"]) is True
    assert await svc.get_document(db_session, doc.id, org_id=two_orgs["org_a"]) is None


@pytest.mark.asyncio
async def test_list_documents_is_org_scoped(db_session: AsyncSession, two_orgs: dict):
    svc = KnowledgeService()
    doc_a = await svc.ingest_document(
        db_session,
        title="A doc",
        content="alpha content " * 30,
        source_type="runbook",
        org_id=two_orgs["org_a"],
    )
    doc_b = await svc.ingest_document(
        db_session,
        title="B doc",
        content="bravo content " * 30,
        source_type="runbook",
        org_id=two_orgs["org_b"],
    )
    await db_session.flush()

    rows_a, _ = await svc.list_documents(db_session, org_id=two_orgs["org_a"])
    ids_a = {r.id for r in rows_a}
    assert doc_a.id in ids_a
    assert doc_b.id not in ids_a

    rows_b, _ = await svc.list_documents(db_session, org_id=two_orgs["org_b"])
    ids_b = {r.id for r in rows_b}
    assert doc_b.id in ids_b
    assert doc_a.id not in ids_b


@pytest.mark.asyncio
async def test_hybrid_search_is_org_scoped(db_session: AsyncSession, two_orgs: dict):
    """Hybrid search never surfaces another org's chunks.

    The raw vector/keyword SQL needs pgvector + ``ILIKE`` (PostgreSQL); on the
    unit-test SQLite backend it can't execute, so the search half is skipped —
    the scoping filter is still exercised by the ORM-level tests above.
    """
    svc = KnowledgeService()
    await svc.ingest_document(
        db_session,
        title="Org A search doc",
        content="quokkarhythm forensics playbook for org A",
        source_type="runbook",
        org_id=two_orgs["org_a"],
    )
    await db_session.flush()

    try:
        res_b = await svc.hybrid_search(db_session, query="quokkarhythm", org_id=two_orgs["org_b"])
        res_a = await svc.hybrid_search(db_session, query="quokkarhythm", org_id=two_orgs["org_a"])
    except DBAPIError as exc:  # pragma: no cover - depends on DB backend
        pytest.skip(f"hybrid_search SQL requires pgvector/ILIKE: {exc}")

    assert res_b == []
    assert any("quokkarhythm" in r.chunk_content.lower() for r in res_a)


@pytest.mark.asyncio
async def test_auto_index_investigation_scopes_to_investigation_org(
    db_session: AsyncSession, two_orgs: dict
):
    """Auto-indexing keeps the report in the investigation's own tenant."""
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=two_orgs["org_b"],
        title="Org B incident",
        description="cross-tenant leak regression",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.flush()

    svc = KnowledgeService()
    doc = await svc.auto_index_investigation(db_session, inv.id)
    assert doc is not None
    assert doc.org_id == two_orgs["org_b"]
    # Org A must not be able to reach the auto-indexed report.
    assert await svc.get_document(db_session, doc.id, org_id=two_orgs["org_a"]) is None
