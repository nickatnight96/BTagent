"""Read + decide API for hunt-pack suggestions (#120 Phase C -> #112).

`_file_hunt_pack_suggestion` has written these rows since #451, but nothing
could read them: no route, no service read, no UI. A confirmed HIT filed a
suggestion into a table no analyst could reach, which makes the design's
own "an analyst promotes it into a live schedule" impossible. These cover
the surface that closes that loop.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import delete

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow, UserRow
from btagent_backend.db.models_pattern import HuntPackSuggestionRow, PatternHuntProposalRow
from tests.helpers import auth_header

NOW = datetime(2026, 6, 18, tzinfo=UTC)

# A second tenant, to prove the list is org-scoped. Dedicated rather than
# DEFAULT_ORG_ID: the test DB is session-scoped and committed rows persist,
# so borrowing the default org would leak these fixtures into every later
# test — the trap that broke CI in #430 and #450.
OTHER_ORG = "org_pack_suggestion_other"


@pytest_asyncio.fixture(autouse=True)
async def _isolate(db_session):
    await db_session.execute(delete(HuntPackSuggestionRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(HuntPackSuggestionRow))
    await db_session.commit()


async def _mk_proposal(db, *, org_id: str = DEFAULT_ORG_ID) -> str:
    """A parent proposal — suggestions FK to pattern_hunt_proposals."""
    row = PatternHuntProposalRow(
        id=generate_id("php"),
        org_id=org_id,
        cluster_id=generate_id("wsc"),
        score=1.0,
        hunt_input={},
        rationale="recurring shape",
        state="accepted",
        created_at=NOW,
        updated_at=NOW,
    )
    db.add(row)
    await db.flush()
    return row.id


async def _mk_suggestion(
    db,
    *,
    org_id: str = DEFAULT_ORG_ID,
    state: str = "suggested",
    hit_count: int = 1,
    title: str = "Recurring: shared-c2.net",
) -> HuntPackSuggestionRow:
    proposal_id = await _mk_proposal(db, org_id=org_id)
    row = HuntPackSuggestionRow(
        id=generate_id("hps"),
        org_id=org_id,
        proposal_id=proposal_id,
        plan_id=generate_id("hunt"),
        title=title,
        technique_ids=["T1059.001"],
        manifest={"name": "recurring", "rules": [{"id": "r1"}]},
        rationale="confirmed by a live hunt",
        state=state,
        hit_count=hit_count,
        created_at=NOW,
        updated_at=NOW,
    )
    db.add(row)
    await db.commit()
    return row


@pytest_asyncio.fixture()
async def senior_token(db_session) -> str:
    """A senior_analyst — holds ``hunt:promote``, which decide requires."""
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"packsenior_{generate_id('n')[-6:]}",
        email=f"packsenior_{generate_id('n')[-6:]}@btagent.test",
        password_hash=hash_password("Senior-P@ss-123!"),
        role="senior_analyst",
        created_at=NOW,
    )
    db_session.add(user)
    await db_session.commit()
    return create_token_pair(user.id, user.username, user.role).access_token


# --- list ------------------------------------------------------------------ #


async def test_list_returns_the_filed_suggestion(
    client: AsyncClient, analyst_token: str, db_session
):
    row = await _mk_suggestion(db_session)

    resp = await client.get("/api/v1/hunts/pack-suggestions", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert [i["id"] for i in items] == [row.id]
    got = items[0]
    assert got["state"] == "suggested"
    assert got["technique_ids"] == ["T1059.001"]
    # The promotable draft ships with the row — an analyst reviews the actual
    # Sigma before arming anything, so it can't be withheld from the list.
    assert got["manifest"]["rules"]


async def test_list_orders_most_reinforced_first(
    client: AsyncClient, analyst_token: str, db_session
):
    """A shape several hunts confirmed outranks one confirmed once."""
    await _mk_suggestion(db_session, hit_count=1, title="once")
    await _mk_suggestion(db_session, hit_count=5, title="five times")

    resp = await client.get("/api/v1/hunts/pack-suggestions", headers=auth_header(analyst_token))
    assert resp.status_code == 200
    assert [i["title"] for i in resp.json()["items"]] == ["five times", "once"]


async def test_list_is_org_scoped(client: AsyncClient, analyst_token: str, db_session):
    if await db_session.get(OrganizationRow, OTHER_ORG) is None:
        db_session.add(OrganizationRow(id=OTHER_ORG, name="Other tenant"))
        await db_session.flush()
    await _mk_suggestion(db_session, org_id=OTHER_ORG, title="not yours")
    mine = await _mk_suggestion(db_session, title="mine")

    resp = await client.get("/api/v1/hunts/pack-suggestions", headers=auth_header(analyst_token))
    assert [i["id"] for i in resp.json()["items"]] == [mine.id]


async def test_list_filters_by_state(client: AsyncClient, analyst_token: str, db_session):
    await _mk_suggestion(db_session, state="suggested", title="open")
    decided = await _mk_suggestion(db_session, state="dismissed", title="closed")

    resp = await client.get(
        "/api/v1/hunts/pack-suggestions?state=dismissed", headers=auth_header(analyst_token)
    )
    assert [i["id"] for i in resp.json()["items"]] == [decided.id]


async def test_list_rejects_an_unknown_state(client: AsyncClient, analyst_token: str):
    resp = await client.get(
        "/api/v1/hunts/pack-suggestions?state=bogus", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 422


async def test_list_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/hunts/pack-suggestions")
    assert resp.status_code in (401, 403)


# --- decide ---------------------------------------------------------------- #


async def test_decide_records_the_analyst_decision(
    client: AsyncClient, senior_token: str, db_session
):
    row = await _mk_suggestion(db_session)

    resp = await client.post(
        f"/api/v1/hunts/pack-suggestions/{row.id}/decide",
        json={"state": "accepted"},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "accepted"

    await db_session.refresh(row)
    assert row.state == "accepted"


async def test_decide_rejects_reverting_to_suggested(
    client: AsyncClient, senior_token: str, db_session
):
    """'suggested' is the writer's initial value, not a decision.

    Allowing it back would hand an analyst a way to un-decide a row, which
    the HIT write-back path treats as still-open and would start refreshing
    again — a state the lifecycle doesn't model.
    """
    row = await _mk_suggestion(db_session)
    resp = await client.post(
        f"/api/v1/hunts/pack-suggestions/{row.id}/decide",
        json={"state": "suggested"},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 422


async def test_decide_on_another_orgs_suggestion_is_404(
    client: AsyncClient, senior_token: str, db_session
):
    """Indistinguishable from 'does not exist' — no cross-tenant probing."""
    if await db_session.get(OrganizationRow, OTHER_ORG) is None:
        db_session.add(OrganizationRow(id=OTHER_ORG, name="Other tenant"))
        await db_session.flush()
    theirs = await _mk_suggestion(db_session, org_id=OTHER_ORG)

    resp = await client.post(
        f"/api/v1/hunts/pack-suggestions/{theirs.id}/decide",
        json={"state": "dismissed"},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 404

    missing = await client.post(
        "/api/v1/hunts/pack-suggestions/hps_nope/decide",
        json={"state": "dismissed"},
        headers=auth_header(senior_token),
    )
    assert missing.status_code == 404


async def test_decide_requires_senior_analyst(client: AsyncClient, analyst_token: str, db_session):
    """A plain analyst can read the queue but not durably decide it.

    A dismiss permanently stops a confirmed-HIT shape re-surfacing, which is
    the same class of action the RBAC map already puts at senior.
    """
    row = await _mk_suggestion(db_session)
    resp = await client.post(
        f"/api/v1/hunts/pack-suggestions/{row.id}/decide",
        json={"state": "dismissed"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403
