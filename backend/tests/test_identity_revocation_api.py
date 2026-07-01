"""Tests for the revoke-playbook proposal flow (#116 Phase C, slice 2).

End-to-end over the HTTP layer:
- promoting identity grant findings attaches a RevocationProposal to the
  investigation config (hunt_triage_service integration)
- GET surfaces the proposal; non-grant promotions have none (404)
- accept is the HITL gate: senior+ only (playbook:create), materialises a
  real playbook via the playbook service, and is idempotent (409 on re-decide)
- reject records the decision without creating a playbook
- org/assignment scoping masks out-of-scope investigations as 404
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.types.hunt import HuntDomain
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, UserRow
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.db.models_playbook import PlaybookRow


def _finding(
    *,
    principal_id: str | None = "alice@example.com",
    app_id: str | None = "app_slack",
    app_display_name: str = "Slack",
    provider: str = "okta",
    scopes: list[str] | None = None,
    title: str = "Dormant OAuth app reactivated",
) -> HuntFindingRow:
    """A HuntFindingRow with the evidence shape the identity detectors emit."""
    evidence: dict = {
        "provider": provider,
        "app_display_name": app_display_name,
        "scopes": scopes if scopes is not None else ["openid", "profile"],
    }
    if principal_id is not None:
        evidence["principal_id"] = principal_id
    if app_id is not None:
        evidence["app_id"] = app_id
    return HuntFindingRow(
        id=generate_id("hfnd"),
        org_id=DEFAULT_ORG_ID,
        source="identity",
        domain=HuntDomain.IDENTITY.value,
        title=title,
        description="",
        severity="medium",
        confidence=0.7,
        state="new",
        technique_ids=["T1078.004"],
        entities=[],
        observables=[],
        evidence=evidence,
        signature="",
        created_at=datetime.now(UTC),
    )


@pytest_asyncio.fixture
async def senior_user(db_session: AsyncSession) -> UserRow:
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"revocation_senior_{generate_id('n')}",
        email=f"revocation_senior_{generate_id('e')}@btagent.test",
        password_hash=hash_password("Str0ng!Passw0rd"),
        role="senior_analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture
async def senior_token(senior_user: UserRow) -> str:
    return create_token_pair(senior_user.id, senior_user.username, senior_user.role).access_token


async def _promote(client, token: str, db_session: AsyncSession, rows: list[HuntFindingRow]) -> str:
    """Seed findings and promote them; returns the new investigation id."""
    for row in rows:
        db_session.add(row)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/hunt/findings/promote",
        headers=auth_header(token),
        json={"finding_ids": [r.id for r in rows]},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["investigation_id"]


def _proposal_url(investigation_id: str) -> str:
    return f"/api/v1/identity/investigations/{investigation_id}/revocation-proposal"


# --------------------------------------------------------------------------- #
# Promote attaches (or doesn't attach) a proposal
# --------------------------------------------------------------------------- #


async def test_promote_of_grant_findings_attaches_proposal(
    client, senior_token, db_session: AsyncSession
):
    rows = [
        _finding(scopes=["openid"]),
        _finding(scopes=["profile", "Mail.Read"]),  # same grant — dedups to one target
        _finding(app_id=None, title="Token replay across ASNs"),  # non-grant, skipped
    ]
    inv_id = await _promote(client, senior_token, db_session, rows)

    resp = await client.get(_proposal_url(inv_id), headers=auth_header(senior_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "proposed"
    assert body["playbook_id"] is None
    assert len(body["targets"]) == 1
    target = body["targets"][0]
    assert target["principal_id"] == "alice@example.com"
    assert target["app_id"] == "app_slack"
    assert sorted(target["scopes"]) == sorted(["openid", "profile", "Mail.Read"])
    # The generated playbook opens with a HITL gate.
    assert body["playbook_spec"]["steps"][0]["type"] == "hitl_gate"


async def test_promote_of_non_grant_findings_has_no_proposal(
    client, senior_token, db_session: AsyncSession
):
    rows = [_finding(app_id=None, title="Token replay across ASNs")]
    inv_id = await _promote(client, senior_token, db_session, rows)

    resp = await client.get(_proposal_url(inv_id), headers=auth_header(senior_token))
    assert resp.status_code == 404


async def test_missing_investigation_is_404(client, senior_token):
    resp = await client.get(_proposal_url("inv_does_not_exist"), headers=auth_header(senior_token))
    assert resp.status_code == 404


async def test_analyst_cannot_read_unassigned_investigation(
    client, senior_token, analyst_token, db_session: AsyncSession
):
    # Promotion by the senior leaves the investigation unassigned to the
    # analyst, so the role-aware scoping masks it as 404.
    inv_id = await _promote(client, senior_token, db_session, [_finding()])
    resp = await client.get(_proposal_url(inv_id), headers=auth_header(analyst_token))
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Accept — the HITL gate
# --------------------------------------------------------------------------- #


async def test_accept_creates_playbook_and_flips_status(
    client, senior_token, senior_user, db_session: AsyncSession
):
    inv_id = await _promote(client, senior_token, db_session, [_finding()])

    resp = await client.post(
        f"{_proposal_url(inv_id)}/accept",
        headers=auth_header(senior_token),
        json={"rationale": "Confirmed malicious consent"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["decided_by"] == senior_user.id
    assert body["decision_rationale"] == "Confirmed malicious consent"
    assert body["playbook_id"]

    # The playbook was really materialised — the generated spec passed the
    # playbook service's schema/DAG validation and landed in the store.
    row = (
        await db_session.execute(select(PlaybookRow).where(PlaybookRow.id == body["playbook_id"]))
    ).scalar_one_or_none()
    assert row is not None
    assert row.trigger_type == "manual"
    assert "hitl_gate" in row.yaml_content

    # The stored proposal reflects the decision on subsequent reads.
    resp = await client.get(_proposal_url(inv_id), headers=auth_header(senior_token))
    assert resp.json()["status"] == "accepted"


async def test_accept_is_not_repeatable(client, senior_token, db_session: AsyncSession):
    inv_id = await _promote(client, senior_token, db_session, [_finding()])
    first = await client.post(
        f"{_proposal_url(inv_id)}/accept", headers=auth_header(senior_token), json={}
    )
    assert first.status_code == 200
    second = await client.post(
        f"{_proposal_url(inv_id)}/accept", headers=auth_header(senior_token), json={}
    )
    assert second.status_code == 409


async def test_analyst_cannot_accept(client, senior_token, analyst_token, db_session: AsyncSession):
    inv_id = await _promote(client, senior_token, db_session, [_finding()])
    resp = await client.post(
        f"{_proposal_url(inv_id)}/accept", headers=auth_header(analyst_token), json={}
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Reject
# --------------------------------------------------------------------------- #


async def test_reject_records_decision_without_playbook(
    client, senior_token, senior_user, db_session: AsyncSession
):
    inv_id = await _promote(client, senior_token, db_session, [_finding()])

    resp = await client.post(
        f"{_proposal_url(inv_id)}/reject",
        headers=auth_header(senior_token),
        json={"rationale": "Grant is sanctioned by IT"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["playbook_id"] is None
    assert body["decided_by"] == senior_user.id
    assert body["decision_rationale"] == "Grant is sanctioned by IT"

    # A rejected proposal can't be accepted afterwards.
    resp = await client.post(
        f"{_proposal_url(inv_id)}/accept", headers=auth_header(senior_token), json={}
    )
    assert resp.status_code == 409
