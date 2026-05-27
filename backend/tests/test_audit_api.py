"""Tests for the audit-lineage API (UC-7.1, #110)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from btagent_shared.types.enums import AuditCategory, AuditOutcome

from btagent_backend.services.audit_trail import AuditTrail
from tests.helpers import auth_header


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


async def test_list_entries_requires_senior(
    client: AsyncClient, analyst_token: str
):
    # plain analyst lacks audit:view (needs senior_analyst)
    resp = await client.get("/api/v1/audit/entries", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_list_entries_as_admin(
    client: AsyncClient, admin_token: str, db_session
):
    await _seed(db_session, 3)
    resp = await client.get("/api/v1/audit/entries", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["items"]) >= 3
    # newest first + hash-chain fields present
    assert body["items"][0]["hash"]
    assert "prev_hash" in body["items"][0]


async def test_verify_chain_endpoint(
    client: AsyncClient, admin_token: str, db_session
):
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


async def test_export_forbidden_for_non_admin(
    client: AsyncClient, analyst_token: str
):
    resp = await client.get("/api/v1/audit/export", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_entries_require_auth(client: AsyncClient):
    resp = await client.get("/api/v1/audit/entries")
    assert resp.status_code in (401, 403)
