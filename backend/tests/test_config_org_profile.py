"""Regression tests for per-org organisation profile isolation (GH #393).

The org profile was stored as a single global row, so any analyst read another
org's profile and an admin's update overwrote the one global row — poisoning
every other org's agent prompts. These tests pin the fix: the profile is
per-org, reads are scoped to the caller's org, and one org's write never
touches another org's row.
"""

import pytest
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient

from btagent_backend.auth.jwt import create_token_pair
from btagent_backend.db.models import OrganizationRow, UserRow

_ORG_PROFILE_URL = "/api/v1/config/org-profile"


async def _make_org_admin(db_session, label: str) -> tuple[str, str]:
    """Create an org + an admin user in it; return (org_id, access_token)."""
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name=f"{label}-{org_id}"))
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"admin-{org_id}",
        email=f"admin-{org_id}@btagent.test",
        password_hash=None,
        role="admin",
    )
    db_session.add(user)
    await db_session.commit()
    token = create_token_pair(user.id, user.username, user.role, org_id=org_id).access_token
    return org_id, token


@pytest.mark.asyncio
async def test_org_profile_is_isolated_per_org(client: AsyncClient, db_session):
    """Cross-tenant read + destructive cross-tenant write are both prevented."""
    _org_a, token_a = await _make_org_admin(db_session, "orgA")
    _org_b, token_b = await _make_org_admin(db_session, "orgB")

    # Org A sets its profile.
    resp = await client.put(
        _ORG_PROFILE_URL,
        json={"industry": "financial_services", "compliance": ["PCI-DSS"]},
        headers=auth_header(token_a),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["profile"]["industry"] == "financial_services"

    # Org B reads its OWN profile — it must NOT see org A's data (default/empty).
    resp = await client.get(_ORG_PROFILE_URL, headers=auth_header(token_b))
    assert resp.status_code == 200, resp.text
    assert resp.json()["profile"]["industry"] == ""
    assert resp.json()["profile"]["compliance"] == []

    # Org B updates its own profile.
    resp = await client.put(
        _ORG_PROFILE_URL,
        json={"industry": "healthcare", "compliance": ["HIPAA"]},
        headers=auth_header(token_b),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["profile"]["industry"] == "healthcare"

    # Org A's profile is UNCHANGED by org B's write — no global-row overwrite.
    resp = await client.get(_ORG_PROFILE_URL, headers=auth_header(token_a))
    assert resp.status_code == 200, resp.text
    assert resp.json()["profile"]["industry"] == "financial_services"
    assert resp.json()["profile"]["compliance"] == ["PCI-DSS"]

    # And org B still reads back its own value (not org A's).
    resp = await client.get(_ORG_PROFILE_URL, headers=auth_header(token_b))
    assert resp.status_code == 200, resp.text
    assert resp.json()["profile"]["industry"] == "healthcare"


@pytest.mark.asyncio
async def test_org_profile_defaults_when_none_saved(client: AsyncClient, db_session):
    """A fresh org with no saved profile gets an empty default, not an error."""
    _org_id, token = await _make_org_admin(db_session, "orgFresh")

    resp = await client.get(_ORG_PROFILE_URL, headers=auth_header(token))
    assert resp.status_code == 200, resp.text
    profile = resp.json()["profile"]
    assert profile["industry"] == ""
    assert profile["compliance"] == []
    assert profile["tech_stack"] == {}
    assert profile["critical_assets"] == []
