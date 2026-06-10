"""Workflow lifecycle audit-trail integration tests (Phase 2 v2, item 2).

Publish / deprecate / auto-deprecate / soft-delete transitions must land on
the SHA-256 hash-chain audit log (category ``workflow``) with the acting
user as ``actor``. These tests drive the real API and then inspect the
``audit_logs`` table + chain integrity directly — following the idiom of
test_audit_trail.py (direct AuditLogRow inspection) and test_audit_api.py
(table isolation around each test, since the shared in-memory DB's
``audit_logs.seq`` is UNIQUE across modules).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow, UserRow
from btagent_backend.services.audit_trail import AuditTrail

_PASSWORD = "TestSenior!2026"

# Minimal engine-valid definition (mirrors ECHO_DEF in test_workflow_run_api.py)
# so the publish gate's Workflow validation passes.
VALID_DEF: dict[str, Any] = {
    "name": "echo-wf",
    "version": "1.0",
    "trigger": {},
    "nodes": [{"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}}],
    "edges": [],
}


@pytest_asyncio.fixture(autouse=True)
async def _isolate_audit_log(db_session: AsyncSession):
    """Clear audit_logs before + after each test (shared in-memory DB)."""
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()


@pytest_asyncio.fixture()
async def senior_user(db_session: AsyncSession) -> UserRow:
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"auditsenior_{generate_id('n')}",
        email=f"auditsenior_{generate_id('e')}@btagent.test",
        password_hash=hash_password(_PASSWORD),
        role="senior_analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture()
async def senior_token(senior_user: UserRow) -> str:
    return create_token_pair(senior_user.id, senior_user.username, senior_user.role).access_token


async def _workflow_audit_rows(db_session: AsyncSession) -> list[AuditLogRow]:
    # NOTE: no expire_all() here — the audit rows are committed by the API's
    # request-scoped session, so this session reads them fresh anyway, and
    # expiring would detach-expire the user fixtures held by the same session.
    rows = await db_session.execute(
        select(AuditLogRow).where(AuditLogRow.category == "workflow").order_by(AuditLogRow.seq)
    )
    return list(rows.scalars().all())


async def _create_workflow(client: AsyncClient, token: str, definition: dict) -> str:
    resp = await client.post(
        "/api/v1/workflows",
        headers=auth_header(token),
        json={"name": "audited-wf", "definition": definition},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_publish_writes_audit_entry(
    client: AsyncClient, db_session: AsyncSession, senior_user: UserRow, senior_token: str
):
    wf_id = await _create_workflow(client, senior_token, VALID_DEF)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 200, resp.text

    rows = await _workflow_audit_rows(db_session)
    assert len(rows) == 1
    entry = rows[0]
    assert entry.action == "publish"
    assert entry.category == "workflow"
    assert entry.actor == senior_user.username
    assert entry.resource == f"workflow:{wf_id}"
    assert entry.outcome == "success"
    assert entry.details["version_number"] == 1


@pytest.mark.asyncio
async def test_publish_v2_audits_auto_deprecate_of_v1(
    client: AsyncClient, db_session: AsyncSession, senior_user: UserRow, senior_token: str
):
    """The implicit deprecate of the prior published version is audited too."""
    wf_id = await _create_workflow(client, senior_token, VALID_DEF)
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": VALID_DEF},
    )
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/2/publish",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 200, resp.text

    rows = await _workflow_audit_rows(db_session)
    actions = [(r.action, r.details.get("version_number")) for r in rows]
    assert actions == [("publish", 1), ("auto_deprecate", 1), ("publish", 2)]
    auto_dep = rows[1]
    assert auto_dep.actor == senior_user.username
    assert auto_dep.resource == f"workflow:{wf_id}"
    assert auto_dep.details["superseded_by_version"] == 2


@pytest.mark.asyncio
async def test_explicit_deprecate_writes_audit_entry(
    client: AsyncClient,
    db_session: AsyncSession,
    senior_token: str,
    admin_user: UserRow,
    admin_token: str,
):
    wf_id = await _create_workflow(client, senior_token, VALID_DEF)
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/deprecate",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text

    rows = await _workflow_audit_rows(db_session)
    assert [r.action for r in rows] == ["publish", "deprecate"]
    dep = rows[-1]
    assert dep.actor == admin_user.username
    assert dep.resource == f"workflow:{wf_id}"
    assert dep.details["version_number"] == 1


@pytest.mark.asyncio
async def test_failed_publish_writes_no_audit_entry(
    client: AsyncClient, db_session: AsyncSession, senior_token: str
):
    """A 409 (validation-rejected) publish must not pollute the ledger."""
    wf_id = await _create_workflow(client, senior_token, {"garbage": True})
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 409
    assert await _workflow_audit_rows(db_session) == []


@pytest.mark.asyncio
async def test_soft_delete_writes_audit_entry(
    client: AsyncClient,
    db_session: AsyncSession,
    senior_token: str,
    admin_user: UserRow,
    admin_token: str,
):
    wf_id = await _create_workflow(client, senior_token, VALID_DEF)
    resp = await client.delete(f"/api/v1/workflows/{wf_id}", headers=auth_header(admin_token))
    assert resp.status_code == 204, resp.text

    rows = await _workflow_audit_rows(db_session)
    assert [r.action for r in rows] == ["delete"]
    assert rows[0].actor == admin_user.username
    assert rows[0].resource == f"workflow:{wf_id}"


@pytest.mark.asyncio
async def test_lifecycle_entries_keep_chain_intact(
    client: AsyncClient, db_session: AsyncSession, senior_token: str, admin_token: str
):
    """The full publish→publish(auto-dep)→deprecate→delete flow verifies clean."""
    wf_id = await _create_workflow(client, senior_token, VALID_DEF)
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish", headers=auth_header(senior_token)
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": VALID_DEF},
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/2/publish", headers=auth_header(senior_token)
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/2/deprecate", headers=auth_header(admin_token)
    )
    await client.delete(f"/api/v1/workflows/{wf_id}", headers=auth_header(admin_token))

    rows = await _workflow_audit_rows(db_session)
    assert [r.action for r in rows] == [
        "publish",
        "auto_deprecate",
        "publish",
        "deprecate",
        "delete",
    ]

    valid, errors = await AuditTrail(db_session).verify_chain()
    assert valid, errors
