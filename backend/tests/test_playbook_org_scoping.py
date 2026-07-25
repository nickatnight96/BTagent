"""Cross-tenant scoping tests for playbook executions (#394).

Playbook execution rows carry sensitive per-run data (``trigger_data``,
``step_results``, and a link to an ``investigation_id``). Before the fix the
list/get execution endpoints filtered on ``playbook:view`` only, never on
tenant, so an org-B analyst could read an org-A org's execution rows.

These tests pin the fix:

* a direct GET of another org's execution returns 404 (not 403)
* an analyst CAN GET an execution in their own org
* the per-playbook execution-history list is org-scoped (excludes other
  orgs' runs, includes the caller's own)
* the ``/execute`` route stamps ``org_id`` from the authenticated caller

Executions are inserted directly via the DB so we can place them in arbitrary
orgs, mirroring ``test_route_idor.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import OrganizationRow, UserRow
from btagent_backend.db.models_playbook import PlaybookExecutionRow, PlaybookRow

_PASSWORD = "Test-P@ss-394!"

_MINIMAL_YAML = """\
name: Scoped PB
trigger:
  type: manual
steps:
  - id: done
    type: end
    name: Done
"""


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
    role: str,
    org_id: str,
    label: str,
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


async def _make_playbook(db: AsyncSession) -> PlaybookRow:
    pb = PlaybookRow(
        id=generate_id("pb"),
        name="Shared Playbook",
        version="1.0",
        description="",
        yaml_content=_MINIMAL_YAML,
        trigger_type="manual",
        trigger_config={},
        is_active=True,
    )
    db.add(pb)
    await db.commit()
    return pb


async def _make_execution(
    db: AsyncSession,
    *,
    playbook: PlaybookRow,
    org_id: str,
) -> PlaybookExecutionRow:
    execution = PlaybookExecutionRow(
        id=generate_id("pbe"),
        org_id=org_id,
        playbook_id=playbook.id,
        investigation_id=None,
        status="completed",
        trigger_data={"secret": f"payload-for-{org_id}"},
        step_results={"done": {"status": "completed"}},
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )
    db.add(execution)
    await db.commit()
    return execution


def _token(user: UserRow) -> str:
    return create_token_pair(user.id, user.username, user.role, org_id=user.org_id).access_token


@pytest_asyncio.fixture()
async def scoping_setup(db_session: AsyncSession):
    """A shared playbook with one execution in org_default and one in org_b,
    plus an analyst in each org."""
    await _ensure_org(db_session, "org_default")
    await _ensure_org(db_session, "org_b")

    playbook = await _make_playbook(db_session)

    org_a_user = await _make_user(db_session, role="analyst", org_id="org_default", label="ana_a")
    org_b_user = await _make_user(db_session, role="analyst", org_id="org_b", label="ana_b")

    exec_a = await _make_execution(db_session, playbook=playbook, org_id="org_default")
    exec_b = await _make_execution(db_session, playbook=playbook, org_id="org_b")

    return {
        "playbook": playbook,
        "org_a_user": org_a_user,
        "org_b_user": org_b_user,
        "exec_a": exec_a,
        "exec_b": exec_b,
    }


# ---------------------------------------------------------------------------
# GET /playbooks/executions/{id} — direct execution fetch.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_org_a_user_can_get_own_execution(client: AsyncClient, scoping_setup):
    """Sanity check: an org-A analyst reads an org-A execution."""
    resp = await client.get(
        f"/api/v1/playbooks/executions/{scoping_setup['exec_a'].id}",
        headers=auth_header(_token(scoping_setup["org_a_user"])),
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == scoping_setup["exec_a"].id


@pytest.mark.asyncio
async def test_cross_org_get_execution_returns_404(client: AsyncClient, scoping_setup):
    """An org-B analyst gets 404 (not 403) for an org-A execution — and never
    sees its trigger_data / step_results."""
    resp = await client.get(
        f"/api/v1/playbooks/executions/{scoping_setup['exec_a'].id}",
        headers=auth_header(_token(scoping_setup["org_b_user"])),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /playbooks/{playbook_id}/executions — history list scoping.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execution_history_is_org_scoped(client: AsyncClient, scoping_setup):
    """The history list for a shared playbook only shows the caller's org's runs."""
    pb_id = scoping_setup["playbook"].id

    resp_a = await client.get(
        f"/api/v1/playbooks/{pb_id}/executions",
        headers=auth_header(_token(scoping_setup["org_a_user"])),
    )
    assert resp_a.status_code == 200
    ids_a = {item["id"] for item in resp_a.json()["items"]}
    assert scoping_setup["exec_a"].id in ids_a
    assert scoping_setup["exec_b"].id not in ids_a

    resp_b = await client.get(
        f"/api/v1/playbooks/{pb_id}/executions",
        headers=auth_header(_token(scoping_setup["org_b_user"])),
    )
    assert resp_b.status_code == 200
    ids_b = {item["id"] for item in resp_b.json()["items"]}
    assert scoping_setup["exec_b"].id in ids_b
    assert scoping_setup["exec_a"].id not in ids_b


# ---------------------------------------------------------------------------
# POST /playbooks/{playbook_id}/execute — org_id stamped from caller.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_stamps_caller_org_id(
    client: AsyncClient, db_session: AsyncSession, scoping_setup
):
    """A senior_analyst in org_b executing a shared playbook produces an
    execution row stamped with org_b — not the default org."""
    senior_b = await _make_user(db_session, role="senior_analyst", org_id="org_b", label="sr_b")
    resp = await client.post(
        f"/api/v1/playbooks/{scoping_setup['playbook'].id}/execute",
        headers=auth_header(_token(senior_b)),
        json={"trigger_data": {"k": "v"}},
    )
    assert resp.status_code == 201
    exec_id = resp.json()["id"]

    row = await db_session.get(PlaybookExecutionRow, exec_id)
    assert row is not None
    assert row.org_id == "org_b"
