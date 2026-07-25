"""Regression tests for GH #385 — the audit ledger must be tenant-scoped.

Before this fix the SHA-256 hash-chained audit ledger had no ``org_id`` column
and the read surfaces (/audit/entries, /audit/lineage, /audit/export) returned
the *global* cross-tenant chain, leaking other orgs' actor / action / resource
(e.g. ``detection_pr:https://github.com/orgA/...``).

These tests pin the invariant: an audit row written for org A must NOT be
returned to a user in org B — while it MUST be returned to a user in org A.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import delete

from btagent_backend.auth.jwt import create_token_pair
from btagent_backend.db.models import AuditLogRow, OrganizationRow
from btagent_backend.services.audit_trail import AuditTrail
from tests.helpers import auth_header

_ORG_A = "org_a_385"
_ORG_B = "org_b_385"


@pytest_asyncio.fixture(autouse=True)
async def _isolate_audit_log(db_session):
    """Clear audit_logs before + after each test (shared in-memory DB)."""
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()


@pytest_asyncio.fixture()
async def two_orgs(db_session):
    """Ensure org A and org B exist so the audit_logs org_id FK is satisfiable."""
    for oid, name in ((_ORG_A, "Org A (385)"), (_ORG_B, "Org B (385)")):
        if await db_session.get(OrganizationRow, oid) is None:
            db_session.add(OrganizationRow(id=oid, name=name, created_at=datetime.now(UTC)))
    await db_session.commit()


def _admin_token(org_id: str) -> str:
    """Mint an admin (audit:view + audit:export) access token bound to ``org_id``."""
    return create_token_pair(
        generate_id("usr"), f"admin_{org_id}", "admin", org_id=org_id
    ).access_token


async def _record(db_session, *, org_id: str, actor: str, action: str, resource: str) -> None:
    await AuditTrail(db_session).record(
        actor=actor,
        category=AuditCategory.AGENT_ACTION,
        action=action,
        resource=resource,
        outcome=AuditOutcome.SUCCESS,
        org_id=org_id,
    )
    await db_session.commit()


async def test_entries_are_scoped_to_caller_org(client: AsyncClient, db_session, two_orgs):
    await _record(
        db_session,
        org_id=_ORG_A,
        actor="alice",
        action="open_pr",
        resource="detection_pr:https://github.com/orgA/detections",
    )
    await _record(
        db_session,
        org_id=_ORG_B,
        actor="bob",
        action="open_pr",
        resource="detection_pr:https://github.com/orgB/detections",
    )

    # Org-B admin must NOT see org-A's entry (the disclosure vector).
    resp_b = await client.get("/api/v1/audit/entries", headers=auth_header(_admin_token(_ORG_B)))
    assert resp_b.status_code == 200, resp_b.text
    items_b = resp_b.json()["items"]
    assert {i["actor"] for i in items_b} == {"bob"}
    assert all("orgA" not in i["resource"] for i in items_b)

    # Org-A admin DOES see org-A's entry (and only that one).
    resp_a = await client.get("/api/v1/audit/entries", headers=auth_header(_admin_token(_ORG_A)))
    assert resp_a.status_code == 200, resp_a.text
    items_a = resp_a.json()["items"]
    assert {i["actor"] for i in items_a} == {"alice"}
    assert all("orgB" not in i["resource"] for i in items_a)


async def test_export_is_scoped_to_caller_org(client: AsyncClient, db_session, two_orgs):
    await _record(
        db_session,
        org_id=_ORG_A,
        actor="alice",
        action="open_pr",
        resource="detection_pr:https://github.com/orgA/detections",
    )
    await _record(db_session, org_id=_ORG_B, actor="bob", action="open_pr", resource="res_b")

    resp = await client.get("/api/v1/audit/export", headers=auth_header(_admin_token(_ORG_B)))
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert "bob" in body
    assert "alice" not in body
    assert "orgA" not in body


async def test_lineage_is_scoped_to_caller_org(client: AsyncClient, db_session, two_orgs):
    # Interleave orgs so the caller's rows are NOT contiguous in the global chain.
    await _record(db_session, org_id=_ORG_A, actor="alice", action="a1", resource="r1")
    await _record(db_session, org_id=_ORG_B, actor="bob", action="b1", resource="r2")
    await _record(db_session, org_id=_ORG_A, actor="alice", action="a2", resource="r3")

    # Org-B admin only sees its single node.
    resp_b = await client.get("/api/v1/audit/lineage", headers=auth_header(_admin_token(_ORG_B)))
    assert resp_b.status_code == 200, resp_b.text
    g_b = resp_b.json()
    assert {n["actor"] for n in g_b["nodes"]} == {"bob"}
    assert len(g_b["nodes"]) == 1

    # Org-A admin sees its two nodes, re-sequenced 0..1 within its own view, and
    # the chain still verifies as intact (linkage checked over the global chain).
    resp_a = await client.get("/api/v1/audit/lineage", headers=auth_header(_admin_token(_ORG_A)))
    assert resp_a.status_code == 200, resp_a.text
    g_a = resp_a.json()
    assert {n["actor"] for n in g_a["nodes"]} == {"alice"}
    assert len(g_a["nodes"]) == 2
    assert [n["sequence"] for n in g_a["nodes"]] == [0, 1]
    assert g_a["intact"] is True
    assert g_a["broken_at"] is None


async def test_lineage_up_to_hash_cannot_probe_other_org(client: AsyncClient, db_session, two_orgs):
    """A tenant can't use up_to_hash as an existence oracle for another org."""
    await _record(db_session, org_id=_ORG_A, actor="alice", action="a1", resource="r1")

    # Org-A admin grabs its own row hash.
    g_a = (
        await client.get("/api/v1/audit/lineage", headers=auth_header(_admin_token(_ORG_A)))
    ).json()
    a_hash = g_a["nodes"][0]["id"]

    # Org-B admin asking to replay to org-A's hash gets 404 (not a leak / 200).
    resp = await client.get(
        f"/api/v1/audit/lineage?up_to_hash={a_hash}",
        headers=auth_header(_admin_token(_ORG_B)),
    )
    assert resp.status_code == 404
