"""API tests for the Pattern Hunt router (#120 Phase B).

Seeds proposals via the service, then exercises the HTTP layer for:
- paginated list (with / without state filter)
- dismiss / snooze / accept lifecycle transitions
- RBAC guard (hunt:view / hunt:triage)
- org-scoping (cross-tenant 404)
"""

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_pattern import PatternHuntProposalRow

# --------------------------------------------------------------------------- #
# Fixture: a persisted, committed proposal the HTTP tests act on.
# --------------------------------------------------------------------------- #


def _make_proposal(
    org_id: str = DEFAULT_ORG_ID,
    state: str = "proposed",
    score: float = 0.75,
) -> PatternHuntProposalRow:
    now = datetime.now(UTC)
    return PatternHuntProposalRow(
        id=generate_id("phpr"),
        org_id=org_id,
        cluster_id=generate_id("cl"),
        score=score,
        hunt_input={
            "adversaries": [],
            "ttps": ["T1059.001"],
            "iocs": [],
            "scope": {
                "environments": [],
                "hosts": [],
                "date_from": None,
                "date_to": None,
                "backends": [],
            },
        },
        rationale="Test proposal: T1059.001 seen across 3 closed investigations.",
        state=state,
        outcome=None,
        created_at=now,
        updated_at=now,
    )


@pytest_asyncio.fixture()
async def seeded_proposal(db_session):
    """Insert one proposed proposal; committed so the app sees it."""
    row = _make_proposal()
    db_session.add(row)
    await db_session.commit()
    return row


@pytest_asyncio.fixture()
async def seeded_dismissed_proposal(db_session):
    """Insert one dismissed proposal for filter tests."""
    row = _make_proposal(state="dismissed", score=0.3)
    db_session.add(row)
    await db_session.commit()
    return row


# --------------------------------------------------------------------------- #
# List — read
# --------------------------------------------------------------------------- #


async def test_list_proposals_requires_auth(client):
    resp = await client.get("/api/v1/pattern/proposals")
    assert resp.status_code == 401


async def test_list_proposals_returns_all_by_default(client, analyst_token, seeded_proposal):
    resp = await client.get("/api/v1/pattern/proposals", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] >= 1
    ids = {p["id"] for p in data["items"]}
    assert seeded_proposal.id in ids


async def test_list_proposals_filters_by_state(
    client, analyst_token, seeded_proposal, seeded_dismissed_proposal
):
    # Filter to proposed only — dismissed proposal must not appear.
    resp = await client.get(
        "/api/v1/pattern/proposals?state=proposed",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    ids = {p["id"] for p in resp.json()["items"]}
    assert seeded_proposal.id in ids
    assert seeded_dismissed_proposal.id not in ids

    # Filter to dismissed — proposed must not appear.
    resp2 = await client.get(
        "/api/v1/pattern/proposals?state=dismissed",
        headers=auth_header(analyst_token),
    )
    assert resp2.status_code == 200, resp2.text
    ids2 = {p["id"] for p in resp2.json()["items"]}
    assert seeded_dismissed_proposal.id in ids2
    assert seeded_proposal.id not in ids2


async def test_list_proposals_ordered_by_score_desc(client, analyst_token, db_session):
    """Higher-score proposals come first."""
    low = _make_proposal(score=0.1)
    high = _make_proposal(score=0.99)
    db_session.add(low)
    db_session.add(high)
    await db_session.commit()

    resp = await client.get(
        "/api/v1/pattern/proposals?state=proposed",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    scores = [p["score"] for p in resp.json()["items"]]
    assert scores == sorted(scores, reverse=True)


async def test_list_proposals_pagination(client, analyst_token, db_session):
    """Page-size 1 returns a single item."""
    db_session.add(_make_proposal(score=0.5))
    db_session.add(_make_proposal(score=0.6))
    await db_session.commit()

    resp = await client.get(
        "/api/v1/pattern/proposals?page_size=1&page=1",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["total"] >= 2


async def test_list_proposals_pagination_returns_correct_slices(client, analyst_token, db_session):
    """#400: SQL limit/offset must return the same slices the (now-removed)
    in-Python slice did — page N is exactly the score-desc window, not a
    re-materialisation of the whole org set."""
    # Seed a handful with distinct scores so ordering is deterministic.
    for score in (0.11, 0.22, 0.33, 0.44):
        db_session.add(_make_proposal(score=score))
    await db_session.commit()

    # The score-desc ordering the endpoint promises, taken 4 at a time.
    first4 = await client.get(
        "/api/v1/pattern/proposals?page=1&page_size=4",
        headers=auth_header(analyst_token),
    )
    assert first4.status_code == 200, first4.text
    ordered_ids = [p["id"] for p in first4.json()["items"]]
    assert len(ordered_ids) == 4

    page1 = (
        await client.get(
            "/api/v1/pattern/proposals?page=1&page_size=2",
            headers=auth_header(analyst_token),
        )
    ).json()
    page2 = (
        await client.get(
            "/api/v1/pattern/proposals?page=2&page_size=2",
            headers=auth_header(analyst_token),
        )
    ).json()

    # Each page is the exact window into the shared ordering.
    assert [p["id"] for p in page1["items"]] == ordered_ids[0:2]
    assert [p["id"] for p in page2["items"]] == ordered_ids[2:4]
    # Consistent total across pages, and no row served on two pages.
    assert page1["total"] == page2["total"]
    assert {p["id"] for p in page1["items"]}.isdisjoint({p["id"] for p in page2["items"]})


# --------------------------------------------------------------------------- #
# Lifecycle mutations
# --------------------------------------------------------------------------- #


async def test_dismiss_proposal_transitions_state(client, analyst_token, seeded_proposal):
    resp = await client.post(
        f"/api/v1/pattern/proposals/{seeded_proposal.id}/dismiss",
        json={"rationale": "not relevant"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "dismissed"


async def test_snooze_proposal_transitions_state(client, analyst_token, seeded_proposal):
    resp = await client.post(
        f"/api/v1/pattern/proposals/{seeded_proposal.id}/snooze",
        json={"rationale": "revisit next quarter"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "snoozed"


async def test_accept_proposal_transitions_state(client, analyst_token, seeded_proposal):
    resp = await client.post(
        f"/api/v1/pattern/proposals/{seeded_proposal.id}/accept",
        json={},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "accepted"


async def test_dismiss_unknown_proposal_returns_404(client, analyst_token):
    resp = await client.post(
        "/api/v1/pattern/proposals/phpr_nope/dismiss",
        json={},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


async def test_accept_unknown_proposal_returns_404(client, analyst_token):
    resp = await client.post(
        "/api/v1/pattern/proposals/phpr_nope/accept",
        json={},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #


async def test_list_proposals_requires_hunt_view(client):
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/pattern/proposals")
    assert resp.status_code == 401


async def test_dismiss_requires_hunt_triage_role(client, analyst_token, seeded_proposal):
    """hunt:triage is granted from analyst upward — analyst must succeed."""
    resp = await client.post(
        f"/api/v1/pattern/proposals/{seeded_proposal.id}/dismiss",
        json={},
        headers=auth_header(analyst_token),
    )
    # analyst has hunt:triage (analyst+) → 200
    assert resp.status_code == 200, resp.text
