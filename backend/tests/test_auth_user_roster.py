"""``GET /auth/users`` — the org roster behind admin session revocation.

``POST /auth/revoke/{user_id}`` (#142) has been implemented, tenant-scoped and
admin-only since it landed, and has never had a caller: there was no endpoint
anywhere in the product that listed users, so nothing could name a revocation
target. These tests cover the roster that fixes that.

The properties worth pinning are the ones a mistake here would cost:

* it is **admin-gated**, matching the revoke it feeds rather than the more
  permissive ``user:view``;
* it is **org-scoped with no widening parameter**, so it cannot become a
  cross-tenant account enumeration;
* it **never emits a password hash**, in a response assembled field by field
  precisely so a future column on ``UserRow`` can't leak by default.

Note on the shared in-memory DB: committed rows leak between tests in this
suite, so every assertion below is about *containment*, never about counts.
"""

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy import select

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import OrganizationRow, UserRow

_OTHER_ORG = "org_roster_other"


@pytest_asyncio.fixture()
async def other_org_user(db_session) -> UserRow:
    """A user belonging to a *different* tenant than the admin fixtures."""
    if await db_session.get(OrganizationRow, _OTHER_ORG) is None:
        db_session.add(
            OrganizationRow(id=_OTHER_ORG, name="Roster Other Tenant", created_at=datetime.now(UTC))
        )
        await db_session.commit()

    # Idempotent: this suite shares one in-memory DB and `db_session` only
    # rolls back, so a committed row from an earlier test is still here and a
    # blind insert trips the unique constraint on username/email.
    existing = (
        await db_session.execute(select(UserRow).where(UserRow.username == "roster_outsider"))
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    user = UserRow(
        id=generate_id("usr"),
        org_id=_OTHER_ORG,
        username="roster_outsider",
        email="outsider@other.test",
        password_hash=hash_password("Outsider-P@ss-1!"),
        role="analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture()
async def sso_user(db_session) -> UserRow:
    """An SSO-provisioned user — no local password hash (#144 Phase 1b)."""
    existing = (
        await db_session.execute(select(UserRow).where(UserRow.username == "roster_sso_user"))
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    user = UserRow(
        id=generate_id("usr"),
        org_id="org_default",
        username="roster_sso_user",
        email="sso@btagent.test",
        password_hash=None,
        role="analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.mark.asyncio
async def test_admin_sees_own_org_roster(
    client: AsyncClient, admin_token: str, admin_user: UserRow, sample_user: UserRow
):
    """An admin gets the users of their own org, with the fields the console needs."""
    resp = await client.get("/api/v1/auth/users", headers=auth_header(admin_token))
    assert resp.status_code == 200

    by_id = {u["id"]: u for u in resp.json()}
    assert admin_user.id in by_id
    assert sample_user.id in by_id

    row = by_id[sample_user.id]
    assert row["username"] == sample_user.username
    assert row["role"] == "analyst"
    # last_login is nullable and these fixtures have never logged in — the
    # console has to render that case, so the field must be present as null
    # rather than absent.
    assert "last_login" in row


@pytest.mark.asyncio
async def test_roster_never_emits_a_password_hash(client: AsyncClient, admin_token: str):
    """No credential material in the response, for any user, ever."""
    resp = await client.get("/api/v1/auth/users", headers=auth_header(admin_token))
    assert resp.status_code == 200
    # Checked over the raw text, not the parsed rows: a hash leaking under a
    # differently-named key would still be a leak.
    assert "password" not in resp.text.lower()


@pytest.mark.asyncio
async def test_analyst_cannot_read_the_roster(client: AsyncClient, analyst_token: str):
    """The roster is admin-only — it is the target picker for revocation."""
    resp = await client.get("/api/v1/auth/users", headers=auth_header(analyst_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_senior_analyst_cannot_read_the_roster(client: AsyncClient):
    """``user:view`` (senior) is deliberately *not* enough (AUTH-B1 rationale).

    This is the test that would fail if someone later "fixed the
    inconsistency" of gating a read on ``user:edit``. Loosening it would hand
    account enumeration to a role that cannot act on the result.
    """
    token = create_token_pair(
        generate_id("usr"), "roster_senior", "senior_analyst", org_id="org_default"
    ).access_token
    resp = await client.get("/api/v1/auth/users", headers=auth_header(token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_roster_excludes_other_tenants(
    client: AsyncClient, admin_token: str, other_org_user: UserRow
):
    """AUTH-B1: an admin cannot see, and so cannot revoke, another org's users."""
    resp = await client.get("/api/v1/auth/users", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert other_org_user.id not in {u["id"] for u in resp.json()}


@pytest.mark.asyncio
async def test_other_tenant_admin_sees_only_their_own(
    client: AsyncClient, admin_user: UserRow, other_org_user: UserRow
):
    """The scoping holds from the other side too — not just an empty-list artefact."""
    token = create_token_pair(
        generate_id("usr"), "roster_other_admin", "admin", org_id=_OTHER_ORG
    ).access_token
    resp = await client.get("/api/v1/auth/users", headers=auth_header(token))
    assert resp.status_code == 200

    ids = {u["id"] for u in resp.json()}
    assert other_org_user.id in ids
    assert admin_user.id not in ids


@pytest.mark.asyncio
async def test_sso_users_are_flagged(client: AsyncClient, admin_token: str, sso_user: UserRow):
    """``sso_only`` marks users for whom revocation is the only available lever.

    There is no local password to rotate, so an admin responding to a
    compromise needs to see that before choosing what to do.
    """
    resp = await client.get("/api/v1/auth/users", headers=auth_header(admin_token))
    by_id = {u["id"]: u for u in resp.json()}
    assert by_id[sso_user.id]["sso_only"] is True


@pytest.mark.asyncio
async def test_local_password_users_are_not_flagged(
    client: AsyncClient, admin_token: str, sample_user: UserRow
):
    """The converse, so the flag can't pass by being unconditionally true."""
    resp = await client.get("/api/v1/auth/users", headers=auth_header(admin_token))
    by_id = {u["id"]: u for u in resp.json()}
    assert by_id[sample_user.id]["sso_only"] is False


@pytest.mark.asyncio
async def test_roster_requires_authentication(client: AsyncClient):
    """No token, no roster."""
    resp = await client.get("/api/v1/auth/users")
    assert resp.status_code in (401, 403)
