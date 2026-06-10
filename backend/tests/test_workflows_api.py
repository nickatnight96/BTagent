"""Phase 2 v1/v2 — workflow CRUD + version lifecycle API tests.

Covers:
* CRUD round-trip on the workflow identity row
* Version create / patch / list (+ pagination, Phase 2 v2)
* The single-published-version-per-workflow invariant on publish
* Lifecycle 409s: edit-after-publish, publish-twice, deprecate-draft
* Publish-gate definition validation (engine ``Workflow``) — drafts stay loose
* version_number race: one auto-retry, second collision → 409
* Soft-delete: admin-gated DELETE, list/get exclusion, audit-trail rows kept
* RBAC: analyst CRUD denied, senior_analyst create+publish allowed,
  admin deprecate-explicit allowed
* IDOR: cross-org workflow returns 404 (not 403, not 200)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow, UserRow
from btagent_backend.db.models_workflow import WorkflowRow, WorkflowRunRow, WorkflowVersionRow

_PASSWORD = "TestSenior!2026"

# Minimal definition that passes the engine ``Workflow`` publish gate (same
# shape as ECHO_DEF in test_workflow_run_api.py): one manual-trigger node,
# no edges. Publishing now validates the definition, so every test that
# publishes uses this instead of ``{}``.
VALID_DEF: dict[str, Any] = {
    "name": "echo-wf",
    "version": "1.0",
    "description": "echo trigger payload",
    "trigger": {},
    "nodes": [{"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}}],
    "edges": [],
}


# --------------------------------------------------------------------------- #
# Local fixtures
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture(autouse=True)
async def _isolate_audit_log(db_session: AsyncSession):
    """Clear audit_logs before + after each test in this module.

    Publish / deprecate / delete now write audit rows via AuditTrail.record()
    (seq = max+1). test_audit_trail.py assigns seq from its own module-global
    counter starting at 1, so leftover rows from here would collide on the
    audit_logs.seq UNIQUE constraint (same isolation idiom as
    test_audit_api.py / test_sso_link.py).
    """
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
        json={"name": "wf", "definition": VALID_DEF},
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
        json={"definition": VALID_DEF},
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
        json={"name": "wf", "definition": VALID_DEF},
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
        json={"name": "wf", "definition": VALID_DEF},
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
        json={"name": "wf", "definition": VALID_DEF},
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
    from btagent_backend.db.models import OrganizationRow

    # Seed the foreign org first so the FK from ``workflows.org_id`` is
    # satisfied; the test wants a *real* row in a different tenant, not
    # a fabricated id.
    foreign_org_id = f"org_{generate_id('foreign')}"
    db_session.add(
        OrganizationRow(
            id=foreign_org_id,
            name=f"Foreign Org {foreign_org_id}",
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    foreign_wf = WorkflowRow(
        id=generate_id("wf"),
        name="foreign",
        description="",
        org_id=foreign_org_id,
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
        json={"name": "wf", "definition": VALID_DEF},
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
        json={"definition": VALID_DEF},
    )
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions/2/publish",
        headers=auth_header(senior_token),
    )
    # v3 -> publish
    await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": VALID_DEF},
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


# --------------------------------------------------------------------------- #
# Publish-gate definition validation (Phase 2 v2, item 1)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_publish_garbage_definition_409(client: AsyncClient, senior_token: str):
    """A definition that fails engine Workflow validation must 409 on publish."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        # No "name", "steps" is not a Workflow field (extra=forbid) -> garbage.
        json={"name": "wf", "definition": {"steps": ["a", "b"]}},
    )
    wf_id = create.json()["id"]

    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 409, resp.text
    assert "validation" in resp.json()["detail"].lower()

    # The draft must NOT have transitioned.
    v1 = await client.get(
        f"/api/v1/workflows/{wf_id}/versions/1",
        headers=auth_header(senior_token),
    )
    assert v1.json()["state"] == "draft"


@pytest.mark.asyncio
async def test_publish_empty_definition_409(client: AsyncClient, senior_token: str):
    """The default empty ``{}`` draft is not publishable (missing name)."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_publish_valid_definition_succeeds(client: AsyncClient, senior_token: str):
    """A definition that parses as an engine Workflow still publishes fine."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf", "definition": VALID_DEF},
    )
    wf_id = create.json()["id"]

    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/publish",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "published"


@pytest.mark.asyncio
async def test_draft_edits_stay_loose(client: AsyncClient, senior_token: str):
    """Validation gates ONLY publish — a garbage draft PATCH is still a 200."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "wf"},
    )
    wf_id = create.json()["id"]

    patch = await client.patch(
        f"/api/v1/workflows/{wf_id}/versions/1",
        headers=auth_header(senior_token),
        json={"definition": {"not": "a workflow", "at": ["all"]}},
    )
    assert patch.status_code == 200, patch.text


# --------------------------------------------------------------------------- #
# version_number race (Phase 2 v2, item 3)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_version_race_retries_once(
    db_session: AsyncSession, senior_user: UserRow, monkeypatch
):
    """A stale max-version read (simulated concurrent writer) is retried once.

    First ``_next_version_number`` call returns the already-taken slot 1;
    the IntegrityError is rolled back and the retry re-reads the real max,
    landing the new draft on version 2 instead of surfacing a 500.
    """
    from btagent_backend.services import workflow_service

    wf, _v1 = await workflow_service.create_workflow(
        db_session,
        name="race-wf",
        description="",
        org_id=DEFAULT_ORG_ID,
        created_by=senior_user.id,
    )
    await db_session.commit()

    real_next = workflow_service._next_version_number
    calls = {"n": 0}

    async def stale_once(db, workflow_id):
        calls["n"] += 1
        if calls["n"] == 1:
            return 1  # stale: slot 1 is already taken by v1
        return await real_next(db, workflow_id)

    monkeypatch.setattr(workflow_service, "_next_version_number", stale_once)

    version = await workflow_service.create_version(
        db_session, workflow=wf, definition={}, created_by=senior_user.id
    )
    assert version.version_number == 2
    assert calls["n"] == 2  # initial read + post-rollback retry read


@pytest.mark.asyncio
async def test_create_version_double_collision_raises(
    db_session: AsyncSession, senior_user: UserRow, monkeypatch
):
    """If the retry ALSO collides, the service raises ValueError (route -> 409)."""
    from btagent_backend.services import workflow_service

    wf, _v1 = await workflow_service.create_workflow(
        db_session,
        name="race-wf-2",
        description="",
        org_id=DEFAULT_ORG_ID,
        created_by=senior_user.id,
    )
    await db_session.commit()

    async def always_stale(db, workflow_id):
        return 1  # forever claims the taken slot

    monkeypatch.setattr(workflow_service, "_next_version_number", always_stale)

    with pytest.raises(ValueError, match="conflict"):
        await workflow_service.create_version(
            db_session, workflow=wf, definition={}, created_by=senior_user.id
        )


@pytest.mark.asyncio
async def test_create_version_double_collision_409_via_api(
    client: AsyncClient, senior_token: str, monkeypatch
):
    """API surface of the pathological double-collision: 409, not 500."""
    from btagent_backend.services import workflow_service

    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "race-api"},
    )
    wf_id = create.json()["id"]

    async def always_stale(db, workflow_id):
        return 1

    monkeypatch.setattr(workflow_service, "_next_version_number", always_stale)

    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
        json={"definition": {}},
    )
    assert resp.status_code == 409, resp.text


# --------------------------------------------------------------------------- #
# Version-list pagination (Phase 2 v2, item 4)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_versions_paginated(client: AsyncClient, senior_token: str):
    """page/page_size window the version list; total stays the full count."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "paged"},
    )
    wf_id = create.json()["id"]
    for _ in range(2):  # v2, v3 on top of the seeded v1
        r = await client.post(
            f"/api/v1/workflows/{wf_id}/versions",
            headers=auth_header(senior_token),
            json={"definition": {}},
        )
        assert r.status_code == 201, r.text

    # Middle page of size 1 -> exactly v2 (asc ordering), total still 3.
    page2 = await client.get(
        f"/api/v1/workflows/{wf_id}/versions?page=2&page_size=1",
        headers=auth_header(senior_token),
    )
    assert page2.status_code == 200, page2.text
    body = page2.json()
    assert body["total"] == 3
    assert len(body["items"]) == 1
    assert body["items"][0]["version_number"] == 2

    # Default (no params) still returns everything, oldest-first.
    full = await client.get(
        f"/api/v1/workflows/{wf_id}/versions",
        headers=auth_header(senior_token),
    )
    assert [v["version_number"] for v in full.json()["items"]] == [1, 2, 3]
    assert full.json()["total"] == 3

    # Past-the-end page: empty items, total unchanged.
    page9 = await client.get(
        f"/api/v1/workflows/{wf_id}/versions?page=9&page_size=2",
        headers=auth_header(senior_token),
    )
    assert page9.json()["items"] == []
    assert page9.json()["total"] == 3


@pytest.mark.asyncio
async def test_list_versions_rejects_bad_page_params(client: AsyncClient, senior_token: str):
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "paged-bad"},
    )
    wf_id = create.json()["id"]
    resp = await client.get(
        f"/api/v1/workflows/{wf_id}/versions?page=0",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 422
    resp = await client.get(
        f"/api/v1/workflows/{wf_id}/versions?page_size=999",
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Soft-delete (Phase 2 v2, item 5)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_delete_workflow_requires_admin(
    client: AsyncClient, senior_token: str, analyst_token: str
):
    """``workflow:delete`` is admin-only — senior_analyst and analyst get 403."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "undeletable"},
    )
    wf_id = create.json()["id"]

    for token in (senior_token, analyst_token):
        resp = await client.delete(
            f"/api/v1/workflows/{wf_id}",
            headers=auth_header(token),
        )
        assert resp.status_code == 403

    # Still visible afterwards.
    get = await client.get(f"/api/v1/workflows/{wf_id}", headers=auth_header(senior_token))
    assert get.status_code == 200


@pytest.mark.asyncio
async def test_delete_workflow_soft_deletes(
    client: AsyncClient,
    db_session: AsyncSession,
    senior_token: str,
    admin_token: str,
):
    """DELETE -> 204; list excludes it; get/versions 404; rows stay in the DB."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(senior_token),
        json={"name": "to-delete", "definition": VALID_DEF},
    )
    wf_id = create.json()["id"]

    resp = await client.delete(f"/api/v1/workflows/{wf_id}", headers=auth_header(admin_token))
    assert resp.status_code == 204, resp.text

    # List no longer contains it.
    listed = await client.get("/api/v1/workflows", headers=auth_header(senior_token))
    assert all(w["id"] != wf_id for w in listed.json()["items"])

    # Direct get + everything nested 404s.
    assert (
        await client.get(f"/api/v1/workflows/{wf_id}", headers=auth_header(senior_token))
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/workflows/{wf_id}/versions", headers=auth_header(senior_token))
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/workflows/{wf_id}/versions/1", headers=auth_header(senior_token))
    ).status_code == 404

    # Deleting again (or any lifecycle action) is a 404, not a 409/500.
    again = await client.delete(f"/api/v1/workflows/{wf_id}", headers=auth_header(admin_token))
    assert again.status_code == 404

    # DB-level: the identity + version rows survive (audit trail), with
    # deleted_at stamped on the workflow.
    from sqlalchemy import select

    wf_row = (
        await db_session.execute(select(WorkflowRow).where(WorkflowRow.id == wf_id))
    ).scalar_one()
    assert wf_row.deleted_at is not None
    version_rows = (
        (
            await db_session.execute(
                select(WorkflowVersionRow).where(WorkflowVersionRow.workflow_id == wf_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(version_rows) == 1


@pytest.mark.asyncio
async def test_delete_workflow_preserves_run_history_in_db(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_token: str,
    analyst_token: str,
):
    """Runs stay in the DB after a soft-delete but 404 through the API."""
    create = await client.post(
        "/api/v1/workflows",
        headers=auth_header(admin_token),
        json={"name": "ran-then-deleted", "definition": VALID_DEF},
    )
    wf_id = create.json()["id"]

    run = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        headers=auth_header(analyst_token),
        json={"trigger_payload": {}},
    )
    assert run.status_code == 201, run.text
    run_id = run.json()["id"]

    resp = await client.delete(f"/api/v1/workflows/{wf_id}", headers=auth_header(admin_token))
    assert resp.status_code == 204

    # API: run history unreachable.
    assert (
        await client.get(f"/api/v1/workflows/{wf_id}/runs", headers=auth_header(analyst_token))
    ).status_code == 404
    assert (
        await client.get(
            f"/api/v1/workflows/{wf_id}/runs/{run_id}", headers=auth_header(analyst_token)
        )
    ).status_code == 404

    # DB: the run row is still there.
    from sqlalchemy import select

    run_row = (
        await db_session.execute(select(WorkflowRunRow).where(WorkflowRunRow.id == run_id))
    ).scalar_one()
    assert run_row.workflow_id == wf_id
