"""Tests for the audit-lineage API (UC-7.1, #110)."""

from __future__ import annotations

import pytest
import pytest_asyncio
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from httpx import AsyncClient
from sqlalchemy import delete

from btagent_backend.db.models import AuditLogRow
from btagent_backend.services.audit_trail import AuditTrail
from tests.helpers import auth_header


@pytest_asyncio.fixture(autouse=True)
async def _isolate_audit_log(db_session):
    """Clear audit_logs before + after each test in this module.

    The in-memory test DB is shared across modules and this module commits
    audit rows via AuditTrail.record() (seq = max+1). The pre-existing
    test_audit_trail.py assigns seq from its own module-global counter, so
    leftover rows from here collide on the audit_logs.seq UNIQUE constraint.
    Cleaning up contains this module's writes.
    """
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()


async def _seed(db_session, n: int = 3):
    trail = AuditTrail(db_session)
    for i in range(n):
        await trail.record(
            actor=f"usr_{i}",
            category=AuditCategory.AGENT_ACTION,
            action=f"action_{i}",
            resource=f"res_{i}",
            outcome=AuditOutcome.SUCCESS,
        )
    await db_session.commit()


# --- view (senior-analyst) ------------------------------------------------- #


async def test_list_entries_requires_senior(client: AsyncClient, analyst_token: str):
    # plain analyst lacks audit:view (needs senior_analyst)
    resp = await client.get("/api/v1/audit/entries", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_list_entries_as_admin(client: AsyncClient, admin_token: str, db_session):
    await _seed(db_session, 3)
    resp = await client.get("/api/v1/audit/entries", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["items"]) >= 3
    # newest first + hash-chain fields present
    assert body["items"][0]["hash"]
    assert "prev_hash" in body["items"][0]


async def test_verify_chain_endpoint(client: AsyncClient, admin_token: str, db_session):
    # NOTE: the in-memory test DB is shared across modules, so other tests'
    # audit rows coexist here and a *global* chain verify is not necessarily
    # clean. We assert the endpoint contract (status + response shape +
    # boolean validity), not a pristine-chain outcome which this suite can't
    # guarantee in isolation. Chain-integrity-over-a-clean-chain is covered
    # by test_audit_trail.py.
    await _seed(db_session, 4)
    resp = await client.get("/api/v1/audit/verify", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body["valid"], bool)
    assert isinstance(body["errors"], list)


# --- export (admin only) --------------------------------------------------- #


async def test_export_csv_admin(client: AsyncClient, admin_token: str, db_session):
    await _seed(db_session, 2)
    resp = await client.get("/api/v1/audit/export", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    text = resp.text
    assert text.splitlines()[0] == "seq,timestamp,actor,category,action,resource,outcome,hash"


async def test_export_forbidden_for_non_admin(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/audit/export", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_entries_require_auth(client: AsyncClient):
    resp = await client.get("/api/v1/audit/entries")
    assert resp.status_code in (401, 403)


# --- lineage (senior-analyst) --------------------------------------------- #


async def test_lineage_requires_senior(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/audit/lineage", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_lineage_empty_ledger(client: AsyncClient, admin_token: str):
    # Autouse fixture cleared audit_logs; the graph should be empty + intact.
    resp = await client.get("/api/v1/audit/lineage", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"nodes": [], "edges": [], "intact": True, "broken_at": None}


async def test_lineage_happy_path(client: AsyncClient, admin_token: str, db_session):
    await _seed(db_session, 4)
    resp = await client.get("/api/v1/audit/lineage", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    g = resp.json()
    assert len(g["nodes"]) == 4
    # Genesis has no incoming edge -> n-1 edges in a linear chain.
    assert len(g["edges"]) == 3
    assert g["intact"] is True
    assert g["broken_at"] is None
    assert [n["sequence"] for n in g["nodes"]] == [0, 1, 2, 3]
    hashes = [n["id"] for n in g["nodes"]]
    for i, e in enumerate(g["edges"], start=1):
        assert e["source"] == hashes[i - 1]
        assert e["target"] == hashes[i]
        assert e["kind"] == "chain"


async def test_lineage_up_to_hash_returns_prefix(client: AsyncClient, admin_token: str, db_session):
    await _seed(db_session, 5)
    full = await client.get("/api/v1/audit/lineage", headers=auth_header(admin_token))
    cutoff_hash = full.json()["nodes"][2]["id"]

    resp = await client.get(
        f"/api/v1/audit/lineage?up_to_hash={cutoff_hash}",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text
    g = resp.json()
    assert len(g["nodes"]) == 3
    assert g["nodes"][-1]["id"] == cutoff_hash
    assert g["intact"] is True


async def test_lineage_detects_tampered_prev_hash(
    client: AsyncClient, admin_token: str, db_session
):
    from sqlalchemy import select

    await _seed(db_session, 3)
    rows = (
        (await db_session.execute(select(AuditLogRow).order_by(AuditLogRow.seq.asc())))
        .scalars()
        .all()
    )
    victim = rows[1]
    victim.prev_hash = "f" * 64
    await db_session.commit()

    resp = await client.get("/api/v1/audit/lineage", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    g = resp.json()
    assert g["intact"] is False
    assert g["broken_at"] == victim.hash
    # Full graph still returned so the UI can highlight the break.
    assert len(g["nodes"]) == 3
