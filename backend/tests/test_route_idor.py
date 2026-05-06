"""IDOR / cross-tenant route-scoping tests (AUTH-B1).

These tests pin the audit Wave 2 IDOR fixes:

* analyst Alice cannot read or write Bob's investigation / IOC
* a senior_analyst can read another analyst's investigation in the same org
* cross-org access is always denied (returns 404, never 200/403)
* LIST endpoints filter by org and (for plain analysts) by ownership
* admin can access cross-investigation in same org
* POST IOC validates the parent investigation is accessible
* mass-assignment of org_id from the request body is ignored — the row is
  created with the caller's org_id

The fixtures here build users/investigations/IOCs directly via the DB so we
can place them in arbitrary orgs and assign them to arbitrary owners.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import (
    InvestigationRow,
    IOCRow,
    OrganizationRow,
    UserRow,
)

# ---------------------------------------------------------------------------
# Fixtures — multi-tenant scaffolding.
# ---------------------------------------------------------------------------


_PASSWORD = "Test-P@ss-789!"


async def _ensure_org(db: AsyncSession, org_id: str) -> None:
    """Create an organization row if it doesn't already exist."""
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
    org_id: str = "org_default",
    label: str | None = None,
) -> UserRow:
    """Create a user with a unique username/email."""
    suffix = generate_id("usr").split("_", 1)[1]
    user = UserRow(
        id=generate_id("usr"),
        username=f"{label or role}_{suffix}",
        email=f"{label or role}_{suffix}@btagent.test",
        password_hash=hash_password(_PASSWORD),
        role=role,
        org_id=org_id,
        created_at=datetime.now(UTC),
    )
    db.add(user)
    await db.commit()
    return user


async def _make_investigation(
    db: AsyncSession,
    *,
    owner: UserRow,
    title: str = "Test Inv",
    org_id: str | None = None,
) -> InvestigationRow:
    inv = InvestigationRow(
        id=generate_id("inv"),
        title=title,
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity="medium",
        tlp_level="green",
        assigned_to=owner.id,
        org_id=org_id or owner.org_id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db.add(inv)
    await db.commit()
    return inv


async def _make_ioc(
    db: AsyncSession,
    *,
    investigation: InvestigationRow,
    value: str = "1.2.3.4",
) -> IOCRow:
    ioc = IOCRow(
        id=generate_id("ioc"),
        investigation_id=investigation.id,
        org_id=investigation.org_id,
        type="ip",
        value=value,
        tlp_level="green",
        confidence=0.7,
        first_seen=datetime.now(UTC),
    )
    db.add(ioc)
    await db.commit()
    return ioc


def _token(user: UserRow) -> str:
    return create_token_pair(user.id, user.username, user.role, org_id=user.org_id).access_token


@pytest_asyncio.fixture()
async def org_a_setup(db_session: AsyncSession):
    """Two analysts in org_default + a senior_analyst + an admin, plus
    each analyst's investigation and one IOC each."""
    await _ensure_org(db_session, "org_default")
    alice = await _make_user(db_session, role="analyst", label="alice")
    bob = await _make_user(db_session, role="analyst", label="bob")
    senior = await _make_user(db_session, role="senior_analyst", label="senior")
    admin = await _make_user(db_session, role="admin", label="admin")

    alice_inv = await _make_investigation(db_session, owner=alice, title="Alice case")
    bob_inv = await _make_investigation(db_session, owner=bob, title="Bob case")

    alice_ioc = await _make_ioc(db_session, investigation=alice_inv, value="10.0.0.1")
    bob_ioc = await _make_ioc(db_session, investigation=bob_inv, value="10.0.0.2")

    return {
        "alice": alice,
        "bob": bob,
        "senior": senior,
        "admin": admin,
        "alice_inv": alice_inv,
        "bob_inv": bob_inv,
        "alice_ioc": alice_ioc,
        "bob_ioc": bob_ioc,
    }


@pytest_asyncio.fixture()
async def cross_org_setup(db_session: AsyncSession, org_a_setup):
    """Add a second organization with its own analyst + investigation."""
    await _ensure_org(db_session, "org_b")
    eve = await _make_user(db_session, role="analyst", org_id="org_b", label="eve")
    eve_inv = await _make_investigation(db_session, owner=eve, title="Eve case", org_id="org_b")
    eve_ioc = await _make_ioc(db_session, investigation=eve_inv, value="10.0.0.99")
    return {
        **org_a_setup,
        "eve": eve,
        "eve_inv": eve_inv,
        "eve_ioc": eve_ioc,
    }


# ---------------------------------------------------------------------------
# Investigation IDOR — same org, different owners.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyst_cannot_get_other_analysts_investigation(client: AsyncClient, org_a_setup):
    """Alice (analyst) gets 404 — not 403 — for Bob's investigation."""
    resp = await client.get(
        f"/api/v1/investigations/{org_a_setup['bob_inv'].id}",
        headers=auth_header(_token(org_a_setup["alice"])),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyst_can_get_own_investigation(client: AsyncClient, org_a_setup):
    """Sanity check: Alice CAN read her own investigation."""
    resp = await client.get(
        f"/api/v1/investigations/{org_a_setup['alice_inv'].id}",
        headers=auth_header(_token(org_a_setup["alice"])),
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == org_a_setup["alice_inv"].id


@pytest.mark.asyncio
async def test_senior_analyst_can_get_other_analysts_investigation(
    client: AsyncClient, org_a_setup
):
    """Senior analyst gets 200 for any investigation in their org."""
    resp = await client.get(
        f"/api/v1/investigations/{org_a_setup['bob_inv'].id}",
        headers=auth_header(_token(org_a_setup["senior"])),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_can_access_any_investigation_in_org(client: AsyncClient, org_a_setup):
    """Admins are org-wide read/write."""
    resp = await client.get(
        f"/api/v1/investigations/{org_a_setup['alice_inv'].id}",
        headers=auth_header(_token(org_a_setup["admin"])),
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# IOC IDOR.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyst_cannot_get_other_analysts_ioc(client: AsyncClient, org_a_setup):
    """Alice cannot read Bob's IOC by id."""
    resp = await client.get(
        f"/api/v1/iocs/{org_a_setup['bob_ioc'].id}",
        headers=auth_header(_token(org_a_setup["alice"])),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyst_cannot_put_other_analysts_ioc(client: AsyncClient, org_a_setup):
    """Alice cannot update Bob's IOC."""
    resp = await client.put(
        f"/api/v1/iocs/{org_a_setup['bob_ioc'].id}",
        headers=auth_header(_token(org_a_setup["alice"])),
        json={"confidence": 0.99},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_post_ioc_with_inaccessible_investigation_returns_404(
    client: AsyncClient, org_a_setup
):
    """Alice posting to Bob's investigation returns 404."""
    resp = await client.post(
        "/api/v1/iocs",
        headers=auth_header(_token(org_a_setup["alice"])),
        json={
            "investigation_id": org_a_setup["bob_inv"].id,
            "type": "ip",
            "value": "10.0.0.123",
        },
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Cross-org isolation.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_org_get_investigation_returns_404(client: AsyncClient, cross_org_setup):
    """A user from org_default cannot read an investigation in org_b."""
    resp = await client.get(
        f"/api/v1/investigations/{cross_org_setup['eve_inv'].id}",
        headers=auth_header(_token(cross_org_setup["alice"])),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_org_admin_still_blocked(client: AsyncClient, cross_org_setup):
    """Even an admin in org_default cannot reach into org_b."""
    resp = await client.get(
        f"/api/v1/investigations/{cross_org_setup['eve_inv'].id}",
        headers=auth_header(_token(cross_org_setup["admin"])),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_org_get_ioc_returns_404(client: AsyncClient, cross_org_setup):
    """Cross-org IOC GET also returns 404."""
    resp = await client.get(
        f"/api/v1/iocs/{cross_org_setup['eve_ioc'].id}",
        headers=auth_header(_token(cross_org_setup["alice"])),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# LIST scoping.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_investigations_excludes_other_orgs(client: AsyncClient, cross_org_setup):
    """Listing as Alice never returns Eve's investigation from org_b."""
    resp = await client.get(
        "/api/v1/investigations",
        headers=auth_header(_token(cross_org_setup["alice"])),
    )
    assert resp.status_code == 200
    body = resp.json()
    returned_ids = {item["id"] for item in body["items"]}
    assert cross_org_setup["eve_inv"].id not in returned_ids


@pytest.mark.asyncio
async def test_list_investigations_analyst_only_sees_own(client: AsyncClient, org_a_setup):
    """Plain analyst's list only contains investigations they're assigned to."""
    resp = await client.get(
        "/api/v1/investigations",
        headers=auth_header(_token(org_a_setup["alice"])),
    )
    assert resp.status_code == 200
    body = resp.json()
    returned_ids = {item["id"] for item in body["items"]}
    assert org_a_setup["alice_inv"].id in returned_ids
    assert org_a_setup["bob_inv"].id not in returned_ids


@pytest.mark.asyncio
async def test_list_investigations_senior_sees_org_wide(client: AsyncClient, org_a_setup):
    """Senior analyst's list contains investigations they don't own (same org)."""
    resp = await client.get(
        "/api/v1/investigations",
        headers=auth_header(_token(org_a_setup["senior"])),
    )
    assert resp.status_code == 200
    body = resp.json()
    returned_ids = {item["id"] for item in body["items"]}
    assert org_a_setup["alice_inv"].id in returned_ids
    assert org_a_setup["bob_inv"].id in returned_ids


# ---------------------------------------------------------------------------
# Mass-assignment defense — caller cannot set org_id via request body.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_investigation_ignores_org_id_in_body(
    client: AsyncClient, db_session: AsyncSession, cross_org_setup
):
    """Sending ``org_id="org_b"`` in the body is ignored — row is in caller's org."""
    alice = cross_org_setup["alice"]
    resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(_token(alice)),
        json={
            "title": "Mass assignment probe",
            "description": "should land in org_default",
            # Attempt to inject a different org_id; CreateInvestigationRequest
            # doesn't declare it so Pydantic drops it, and even if accepted
            # the route sets org_id from user.org_id explicitly.
            "org_id": "org_b",
        },
    )
    assert resp.status_code == 201
    new_id = resp.json()["id"]

    # Check the DB row — org_id should be alice's org, NOT "org_b".
    inv = await db_session.get(InvestigationRow, new_id)
    assert inv is not None
    assert inv.org_id == alice.org_id == "org_default"
