"""Phase 2 v1 — workflow CRUD + version lifecycle API tests.

Covers:
* CRUD round-trip on the workflow identity row
* Version create / patch / list
* The single-published-version-per-workflow invariant on publish
* Lifecycle 409s: edit-after-publish, publish-twice, deprecate-draft
* RBAC: analyst CRUD denied, senior_analyst create+publish allowed,
  admin deprecate-explicit allowed
* IDOR: cross-org workflow returns 404 (not 403, not 200)
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, UserRow
from btagent_backend.db.models_workflow import WorkflowRow, WorkflowVersionRow

_PASSWORD = "TestSenior!2026"


# --------------------------------------------------------------------------- #
# Local fixtures
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def senior_user(db_session: AsyncSession) -> UserRow:
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"testsenior_{generate_id('n')}",
        email=f"senior_{generate_id('e')}@btagent.test",
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


# --------------------------------------------------------------------------- #
# Workflow CRUD round-trip
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_workflow_seeds_draft_v1(client: AsyncClient, senior_token: str):
    """POST /workflows creates the identity row AND a draft v1."""
    resp = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "Phishing Triage v0", "description": "First pass"},
    )
    assert resp.status_code == 201, resp.text
    wf = resp.json()
    assert wf["name"] == "Phishing Triage v0"
    assert wf["description"] == "First pass"
    assert wf["org_id"] == DEFAULT_ORG_ID

    versions = await client.get(
        f"/api/v1/workflows/{wf['id']}/versions",
        headers=auth_header(senior_token),
    )
    assert versions.status_code == 200
    body = versions.json()
    assert body["total"] == 1
    assert body["items"][0]["version_number"] == 1
    assert body["items"][0]["state"] == "draft"


@pytest.mark.asyncio
async def test_list_workflows_scoped_to_org(client: AsyncClient, senior_token: str):
    """GET /workflows returns only the caller's-org workflows."""
    # Create two
    for name in ("WF1", "WF2"):
        r = await client.post(
            "/api/v1/workflows",
            headers=auth_header(senior_token),
            json={"name": name},
        )
        assert r.status_code == 201, r.text

    resp = await client.get("/api/v1/workflows", headers=auth_header(senior_token))
    assert resp.status_code == 200
    items = resp.json()["items"]
    names = {i["name"] for i in items}
    assert {"WF1", "WF2"}.issubset(names)


@pytest.mark.asyncio
async def test_patch_workflow_metadata(client: AsyncClient, senior_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "original"},
    )
    wf_id = create.json()["id"]

    patch = await client.patch(
        f"/api/v1/workflows/{wf_id}",
        headers=auth_header(senior_token),
        json={"name": "renamed", "description": "new desc"},
    )
    assert patch.status_code == 200
    assert patch.json()["name"] == "renamed"
    assert patch.json()["description"] == "new desc"


# --------------------------------------------------------------------------- #
# Versioning
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_version_auto_increments(client: AsyncClient, senior_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "x"},
    )
    wf_id = create.json()["id"]

    # v2
    v2 = await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": {"name": "v2-draft"}},
    )
    assert v2.status_code == 201, v2.text
    assert v2.json()["version_number"] == 2
    assert v2.json()["state"] == "draft"

    # v3
    v3 = await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": {}},
    )
    assert v3.status_code == 201
    assert v3.json()["version_number"] == 3


@pytest.mark.asyncio
async def test_patch_draft_definition(client: AsyncClient, senior_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "edit me"},
    )
    wf_id = create.json()["id"]

    patch = await client.patch(
        f"/api/v1/workflows/{wf_id}/versions/1",
        headers=auth_header(senior_token),
        json={"definition": {"steps": ["a"]}},
    )
    assert patch.status_code == 200
    assert patch.json()["definition"] == {"steps": ["a"]}


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_publish_auto_deprecates_prior(client: AsyncClient, senior_token: str):
    """Publishing v2 must move v1 (currently published) to deprecated."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    # Publish v1
    p1 = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert p1.status_code == 200, p1.text
    assert p1.json()["state"] == "published"
    assert p1.json()["published_at"] is not None

    # Stage v2
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": {}},
    )

    # Publish v2 — v1 should now be deprecated
    p2 = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/2/publish",
        headers=auth_header(senior_token),
    )
    assert p2.status_code == 200
    assert p2.json()["state"] == "published"

    v1_now = await client.get(
        f"/api/v1/workflows/{wf_id}/versions/1",
        headers=auth_header(senior_token),
    )
    assert v1_now.status_code == 200
    assert v1_now.json()["state"] == "deprecated"
    assert v1_now.json()["deprecated_at"] is not None


@pytest.mark.asyncio
async def test_edit_after_publish_409(client: AsyncClient, senior_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )

    edit = await client.patch(
        f"/api/v1/workflows/{wf_id}/versions/1",
        headers=auth_header(senior_token),
        json={"definition": {"steps": []}},
    )
    assert edit.status_code == 409


@pytest.mark.asyncio
async def test_publish_already_published_409(client: AsyncClient, senior_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    p1 = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert p1.status_code == 200

    p1_again = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert p1_again.status_code == 409


@pytest.mark.asyncio
async def test_deprecate_draft_409(client: AsyncClient, senior_token: str, admin_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    # admin tries to deprecate a draft → 409 (drafts are deleted, not deprecated)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/deprecate",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 409


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_analyst_cannot_create_workflow(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/workflows",
        headers=auth_header(analyst_token),
        json={"name": "denied"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_can_list_and_view(
    client: AsyncClient, senior_token: str, analyst_token: str
):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "viewable"},
    )
    wf_id = create.json()["id"]

    listed = await client.get("/api/v1/workflows", headers=auth_header(analyst_token))
    assert listed.status_code == 200
    assert any(w["id"] == wf_id for w in listed.json()["items"])

    one = await client.get(f"/api/v1/workflows/{wf_id}", headers=auth_header(analyst_token))
    assert one.status_code == 200


@pytest.mark.asyncio
async def test_senior_cannot_explicit_deprecate(client: AsyncClient, senior_token: str):
    """``workflow:deprecate`` is admin-only — senior_analyst gets 403."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )

    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/deprecate",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# IDOR (cross-tenant)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_cross_org_workflow_returns_404(
    client: AsyncClient,
    db_session: AsyncSession,
    senior_user: UserRow,
    senior_token: str,
):
    """A workflow owned by a different org must 404 to a caller in DEFAULT_ORG_ID.

    Returning 404 (not 403, not 200) is the IDOR-mitigation pattern used
    by the investigations / IOCs endpoints — we don't confirm-by-status
    that an id exists in another tenant.
    """
    # Seed a workflow row directly in a foreign org.
    foreign_wf = WorkflowRow(
        id=generate_id("wf"),
        name="foreign",
        description="",
        org_id="org_foreign",
        created_by=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(foreign_wf)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/workflows/{foreign_wf.id}",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_workflow_id_returns_404(client: AsyncClient, senior_token: str):
    resp = await client.get(
        "/api/v1/workflows/wf_does_not_exist",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Schema validation (Pydantic 422 on bad input)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_workflow_missing_name_422(client: AsyncClient, senior_token: str):
    resp = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"description": "no name"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_workflow_empty_name_422(client: AsyncClient, senior_token: str):
    resp = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": ""},
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# DB-level invariant
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_only_one_published_at_a_time(
    db_session: AsyncSession,
    client: AsyncClient,
    senior_token: str,
):
    """After multiple publishes, exactly one PUBLISHED row should exist
    per workflow (DB-level cross-check, not just API)."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    # v2 -> publish
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": {}},
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/2/publish",
        headers=auth_header(senior_token),
    )
    # v3 -> publish
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": {}},
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/3/publish",
        headers=auth_header(senior_token),
    )

    from sqlalchemy import func, select

    count_q = (
        select(func.count())
        .select_from(WorkflowVersionRow)
        .where(
            WorkflowVersionRow.workflow_id == wf_id,
            WorkflowVersionRow.state == "published",
        )
    )
    published_count = (await db_session.execute(count_q)).scalar_one()
    assert published_count == 1
