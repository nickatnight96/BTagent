"""``GET /investigations?search=`` filters server-side, across the whole set.

The PunchList has always sent this parameter and the route never declared it,
so FastAPI discarded it and ``InvestigationList`` compensated by filtering the
page it had already fetched. Two consequences, neither of them visible as an
error:

* search was **page-local** — a title that exists on page 3 found nothing while
  the analyst was on page 1; and
* the result count stayed at the *unfiltered* total, so the header disagreed
  with the rows on screen.

These tests pin the behaviour rather than the parameter name
(``test_api_query_param_parity`` covers the name): seed investigations, search,
and assert on which come back and what ``total`` says.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow


def _token() -> str:
    """A search term nothing else in the database can contain.

    Seeded rows are committed, so they outlive the rolled-back ``db_session``
    and are visible to every later test — both in this module and in the rest
    of the suite, which creates investigations through the API (the templates
    seed titles like "Ransomware Response").

    Exact-count assertions therefore need a term unique to *one test*, not just
    to this module. ``test_search_matches_the_title`` originally searched for
    "ransomware": it passed alone and failed under the full randomized suite
    when a sibling's row matched too.
    """
    return "zz" + generate_id("tok").split("_", 1)[1].lower()


async def _seed(
    db: AsyncSession,
    *,
    assigned_to: str,
    title: str,
    description: str = "",
    status: str = InvestigationStatus.INVESTIGATING.value,
) -> str:
    row = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title=title,
        description=description,
        status=status,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=assigned_to,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db.add(row)
    await db.commit()
    return row.id


@pytest.fixture
def token() -> str:
    """A fresh, unique search term for one test."""
    return _token()


async def _search(client: AsyncClient, auth: str, **params) -> dict:
    query = "&".join(f"{k}={v}" for k, v in params.items())
    resp = await client.get(f"/api/v1/investigations?{query}", headers=auth_header(auth))
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_search_matches_the_title(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    wanted = await _seed(
        db_session, assigned_to=admin_user.id, title=f"Ransomware on FINANCE-07 {token}"
    )
    await _seed(db_session, assigned_to=admin_user.id, title="Phishing wave")

    body = await _search(client, admin_token, search=token)

    ids = [i["id"] for i in body["items"]]
    assert wanted in ids
    assert len(ids) == 1


async def test_search_matches_the_description_too(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """The client-side filter this replaces checked description as well.

    Had the server matched only titles, the search would have silently
    *narrowed* when it moved off the client.
    """
    wanted = await _seed(
        db_session,
        assigned_to=admin_user.id,
        title="Unremarkable title",
        description=f"Beaconing {token} every 60s",
    )
    await _seed(db_session, assigned_to=admin_user.id, title="Something else")

    body = await _search(client, admin_token, search=token)

    assert [i["id"] for i in body["items"]] == [wanted]


async def test_search_is_case_insensitive(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    wanted = await _seed(
        db_session, assigned_to=admin_user.id, title=f"LATERAL {token.upper()} spotted"
    )

    body = await _search(client, admin_token, search=token)

    assert [i["id"] for i in body["items"]] == [wanted]


async def test_total_reflects_the_search_not_the_whole_set(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """The count and the rows must describe the same query.

    This is the half the client-side filter could never fix: it could hide
    rows, but ``total`` came from the server's unfiltered count, so the header
    said "42" over a list of 3.
    """
    await _seed(db_session, assigned_to=admin_user.id, title=f"Needle {token} in the stack")
    for n in range(4):
        await _seed(db_session, assigned_to=admin_user.id, title=f"Haystack {n}")

    body = await _search(client, admin_token, search=token)

    assert body["total"] == 1
    assert len(body["items"]) == 1


async def test_search_combines_with_the_status_filter(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """Both narrow; neither replaces the other."""
    wanted = await _seed(
        db_session,
        assigned_to=admin_user.id,
        title=f"Exfil {token}",
        status=InvestigationStatus.CLOSED.value,
    )
    await _seed(
        db_session,
        assigned_to=admin_user.id,
        title=f"Exfil {token}",
        status=InvestigationStatus.INVESTIGATING.value,
    )

    body = await _search(client, admin_token, search=token, status="closed")

    assert [i["id"] for i in body["items"]] == [wanted]


async def test_search_finds_a_row_beyond_the_first_page(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """The regression, stated directly.

    With page_size=2 the target sits outside the first page, which is exactly
    where the old client-side filter could not see it — it only ever examined
    rows already fetched.
    """
    for n in range(5):
        await _seed(db_session, assigned_to=admin_user.id, title=f"Routine check {n}")
    wanted = await _seed(db_session, assigned_to=admin_user.id, title=f"Distinctive {token} case")

    body = await _search(client, admin_token, search=token, page_size=2)

    assert [i["id"] for i in body["items"]] == [wanted]
    assert body["total"] == 1


async def test_a_blank_search_is_not_a_filter(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """An empty box must show everything, not nothing."""
    await _seed(db_session, assigned_to=admin_user.id, title="Anything at all")

    body = await _search(client, admin_token, search="")

    assert body["total"] >= 1


async def test_search_does_not_escape_the_tenant(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """Search is a filter on top of org scoping, never a way around it."""
    from btagent_backend.db.models import OrganizationRow

    db_session.add(
        OrganizationRow(
            id="org_search_other",
            name="Investigation search cross-tenant fixture",
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    other = InvestigationRow(
        id=generate_id("inv"),
        org_id="org_search_other",
        title=f"Cross tenant {token}",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=admin_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(other)
    await db_session.commit()

    body = await _search(client, admin_token, search=token)

    assert other.id not in [i["id"] for i in body["items"]]
    assert body["total"] == 0


async def test_like_metacharacters_are_literal_characters(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, admin_user, token: str
):
    """``%`` and ``_`` typed by an analyst are characters, not patterns.

    Unescaped, ``%`` matches everything and ``_`` matches any single character
    — so searching "100%" would return the whole board and searching
    "WORKSTATION_42" would also match "WORKSTATION-42". Neither is an injection
    risk (the value is a bound parameter and cannot alter the query's
    structure); both are wrong answers.
    """
    wanted = await _seed(
        db_session, assigned_to=admin_user.id, title=f"Disk {token} 100% full alert"
    )
    await _seed(db_session, assigned_to=admin_user.id, title="Unrelated case")

    # A bare "%" must match the row that literally contains one, not both rows.
    body = await _search(client, admin_token, search=f"{token} 100%25")
    assert [i["id"] for i in body["items"]] == [wanted]

    underscore = await _seed(
        db_session, assigned_to=admin_user.id, title=f"Host {token} WORKSTATION_42"
    )
    await _seed(db_session, assigned_to=admin_user.id, title=f"Host {token} WORKSTATION-42")

    body = await _search(client, admin_token, search=f"{token} WORKSTATION_42")
    assert [i["id"] for i in body["items"]] == [underscore]
