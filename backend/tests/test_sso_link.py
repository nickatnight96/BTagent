"""Tests for admin-driven SSO account linking (#169).

The OIDC callback deliberately 409s rather than auto-linking a verified IdP
email to an existing local-password account (takeover defense). These endpoints
give an operator the explicit, audited override. Coverage here:

  * RBAC — link/list/unlink are admin-only; unauth is rejected.
  * Validation — unknown provider (404), unknown user (404), duplicate
    ``(provider, subject)`` (409).
  * Happy path — link creates a row, list filters by user, unlink removes it.
  * Audit — link + unlink each append an ``authorization`` entry to the chain.
  * Behavior — a linked identity makes ``_jit_provision`` resolve the linked
    user directly, bypassing the password-account 409 (the whole point of #169).
"""

from __future__ import annotations

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select

from btagent_backend.config import OIDCProviderConfig, get_settings
from btagent_backend.db.models import AuditLogRow, SSOIdentityRow
from tests.helpers import auth_header

_PROVIDER_KEY = "testidp"
_SUBJECT = "idp-subject-12345"


@pytest_asyncio.fixture()
async def provider():
    """Register a configured SSO provider for the duration of one test.

    Mutates the cached settings in place and pops the key on teardown so the
    no-provider default is preserved for every other test.
    """
    settings = get_settings()
    settings.oidc_providers[_PROVIDER_KEY] = OIDCProviderConfig(
        issuer="https://idp.example.test",
        client_id="btagent-test-client",
        client_secret="test-client-secret",
        redirect_uri="https://app.example.test/api/v1/auth/sso/testidp/callback",
        scopes=["openid", "email", "profile"],
    )
    yield settings.oidc_providers[_PROVIDER_KEY]
    settings.oidc_providers.pop(_PROVIDER_KEY, None)


@pytest_asyncio.fixture(autouse=True)
async def _isolate(db_session):
    """Clear sso_identity + audit rows before/after each test (shared DB)."""
    await db_session.execute(delete(SSOIdentityRow))
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(SSOIdentityRow))
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()


def _link_body(user_id: str, *, subject: str = _SUBJECT, provider: str = _PROVIDER_KEY) -> dict:
    return {
        "user_id": user_id,
        "provider": provider,
        "subject": subject,
        "email": "linked@btagent.test",
    }


# --- RBAC ------------------------------------------------------------------ #


async def test_link_requires_admin(client: AsyncClient, analyst_token: str, sample_user, provider):
    resp = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403


async def test_link_requires_auth(client: AsyncClient, sample_user, provider):
    resp = await client.post("/api/v1/auth/sso/identities", json=_link_body(sample_user.id))
    assert resp.status_code in (401, 403)


async def test_list_requires_admin(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/auth/sso/identities", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_unlink_requires_admin(client: AsyncClient, analyst_token: str):
    resp = await client.delete(
        "/api/v1/auth/sso/identities/sso_does_not_exist", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 403


# --- Validation ------------------------------------------------------------ #


async def test_link_unknown_provider_404(client: AsyncClient, admin_token: str, sample_user):
    resp = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id, provider="nope"),
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404


async def test_link_unknown_user_404(client: AsyncClient, admin_token: str, provider):
    resp = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body("usr_does_not_exist"),
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404


async def test_link_duplicate_conflict(
    client: AsyncClient, admin_token: str, sample_user, provider
):
    first = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )
    assert first.status_code == 201, first.text

    dup = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )
    assert dup.status_code == 409


# --- Happy path: link → list → unlink -------------------------------------- #


async def test_link_creates_identity(client: AsyncClient, admin_token: str, sample_user, provider):
    resp = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"].startswith("sso_")
    assert body["user_id"] == sample_user.id
    assert body["provider"] == _PROVIDER_KEY
    assert body["subject"] == _SUBJECT
    assert body["email"] == "linked@btagent.test"


async def test_list_filtered_by_user(client: AsyncClient, admin_token: str, sample_user, provider):
    created = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )
    identity_id = created.json()["id"]

    listed = await client.get(
        f"/api/v1/auth/sso/identities?user_id={sample_user.id}",
        headers=auth_header(admin_token),
    )
    assert listed.status_code == 200
    ids = [i["id"] for i in listed.json()]
    assert identity_id in ids

    # A different user has no identities.
    other = await client.get(
        "/api/v1/auth/sso/identities?user_id=usr_someone_else",
        headers=auth_header(admin_token),
    )
    assert other.status_code == 200
    assert other.json() == []


async def test_unlink_removes_identity(
    client: AsyncClient, admin_token: str, sample_user, provider, db_session
):
    created = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )
    identity_id = created.json()["id"]

    deleted = await client.delete(
        f"/api/v1/auth/sso/identities/{identity_id}", headers=auth_header(admin_token)
    )
    assert deleted.status_code == 204

    remaining = await db_session.execute(
        select(SSOIdentityRow).where(SSOIdentityRow.id == identity_id)
    )
    assert remaining.scalar_one_or_none() is None


async def test_unlink_unknown_404(client: AsyncClient, admin_token: str):
    resp = await client.delete(
        "/api/v1/auth/sso/identities/sso_missing", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


# --- Audit ----------------------------------------------------------------- #


async def test_link_and_unlink_are_audited(
    client: AsyncClient, admin_token: str, sample_user, provider, db_session
):
    created = await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )
    identity_id = created.json()["id"]
    await client.delete(
        f"/api/v1/auth/sso/identities/{identity_id}", headers=auth_header(admin_token)
    )

    rows = (
        (
            await db_session.execute(
                select(AuditLogRow)
                .where(AuditLogRow.action.in_(["sso.identity.link", "sso.identity.unlink"]))
                .order_by(AuditLogRow.seq.asc())
            )
        )
        .scalars()
        .all()
    )
    actions = [r.action for r in rows]
    assert actions == ["sso.identity.link", "sso.identity.unlink"]
    for r in rows:
        assert r.category == "authorization"
        assert r.outcome == "success"
        assert r.resource == f"user:{sample_user.id}"
        assert r.details["identity_id"] == identity_id


# --- Behavior: linking unblocks the JIT 409 -------------------------------- #


async def test_linked_identity_resolves_in_jit_provision(
    client: AsyncClient, admin_token: str, sample_user, provider, db_session
):
    """After an admin link, the OIDC callback's identity lookup resolves the
    linked (password) user directly — without re-triggering the 409 or the
    verified-email gate."""
    from btagent_backend.api.v1.sso import _jit_provision

    await client.post(
        "/api/v1/auth/sso/identities",
        json=_link_body(sample_user.id),
        headers=auth_header(admin_token),
    )

    # sample_user has a password_hash and we pass an UNVERIFIED email — both of
    # which would otherwise be refused. The pre-existing link makes step 1 hit.
    resolved = await _jit_provision(
        db_session,
        provider=_PROVIDER_KEY,
        subject=_SUBJECT,
        email=None,
        email_verified=False,
        role="analyst",
    )
    assert resolved.id == sample_user.id
