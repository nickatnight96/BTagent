"""Tests for the TAXII 2.1 feed-configuration store + API (#105 / UC-2.1).

Covers the config-store invariants that keep credentials out of the database
(references only, no userinfo in the URL), org-scoping, and the RBAC gate on
the CRUD surface (``taxii:view`` = senior_analyst, ``taxii:manage`` = admin).

Shared-DB isolation: the in-memory SQLite is session-scoped and committed rows
persist for the whole run, so every exact-count assertion here is scoped to a
dedicated per-test organization (``generate_id("org")``) — never to
``DEFAULT_ORG_ID`` at large.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import OrganizationRow, UserRow
from btagent_backend.services import taxii_feed_service as svc

SERVER = "https://taxii.example.test/api1"
COLLECTION = "collection--1f2e3d4c-5b6a-4978-8899-aabbccddeeff"
VALID_REF = "${secret:vault:taxii/anomali_token}"


def _make_org(db_session: AsyncSession) -> OrganizationRow:
    org = OrganizationRow(
        id=generate_id("org"),
        name=f"Org {generate_id('n')}",
        created_at=datetime.now(UTC),
    )
    db_session.add(org)
    return org


async def _make_user(db_session: AsyncSession, *, org_id: str, role: str) -> tuple[UserRow, str]:
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"{role}_{generate_id('u')}",
        email=f"{generate_id('e')}@btagent.test",
        password_hash=hash_password("Taxii-P@ss-105!"),
        role=role,
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    token = create_token_pair(user.id, user.username, user.role).access_token
    return user, token


# --------------------------------------------------------------------------- #
# Service — validation invariants
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_feed_persists_config(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    row = await svc.create_feed(
        db_session,
        org_id=org.id,
        name="Anomali Limo",
        server_url=f"{SERVER}/",  # trailing slash normalised away
        collection_id=COLLECTION,
        auth_style="bearer",
        auth_secret_ref=VALID_REF,
        poll_interval_minutes=30,
        actor_id="usr_admin",
    )
    await db_session.commit()

    assert row.server_url == SERVER
    assert row.auth_secret_ref == VALID_REF
    assert row.poll_interval_minutes == 30
    assert row.enabled is True
    assert row.last_cursor is None
    assert row.last_status == ""


@pytest.mark.asyncio
async def test_create_feed_rejects_inline_secret(db_session: AsyncSession):
    """The core invariant: raw credential material can never reach the table."""
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig) as exc:
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="Inline secret",
            server_url=SERVER,
            collection_id=COLLECTION,
            auth_style="bearer",
            auth_secret_ref="eyJhbGciOiJIUzI1NiJ9.rawtokenmaterial.signature",
        )
    assert "${secret:" in str(exc.value)


@pytest.mark.asyncio
async def test_create_feed_rejects_reference_embedded_in_text(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="Mixed",
            server_url=SERVER,
            collection_id=COLLECTION,
            auth_style="bearer",
            auth_secret_ref=f"Bearer {VALID_REF}",
        )


@pytest.mark.asyncio
async def test_create_feed_rejects_credentials_in_url(db_session: AsyncSession):
    """Userinfo in the URL would be an inline secret by another name."""
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="Userinfo URL",
            server_url="https://svc:hunter2@taxii.example.test/api1",
            collection_id=COLLECTION,
        )


@pytest.mark.asyncio
async def test_create_feed_rejects_non_http_url(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="File URL",
            server_url="file:///etc/passwd",
            collection_id=COLLECTION,
        )


@pytest.mark.asyncio
async def test_auth_none_must_not_carry_a_reference(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="Contradictory auth",
            server_url=SERVER,
            collection_id=COLLECTION,
            auth_style="none",
            auth_secret_ref=VALID_REF,
        )


@pytest.mark.asyncio
async def test_auth_style_requiring_material_needs_a_reference(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="Bearer without ref",
            server_url=SERVER,
            collection_id=COLLECTION,
            auth_style="bearer",
            auth_secret_ref="",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("minutes", [0, 1, 4, 60 * 24 * 8])
async def test_poll_interval_is_bounded(db_session: AsyncSession, minutes: int):
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name=f"Interval {minutes}",
            server_url=SERVER,
            collection_id=COLLECTION,
            poll_interval_minutes=minutes,
        )


@pytest.mark.asyncio
async def test_duplicate_name_within_org_is_rejected(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    await svc.create_feed(
        db_session,
        org_id=org.id,
        name="Dup",
        server_url=SERVER,
        collection_id=COLLECTION,
    )
    await db_session.commit()

    with pytest.raises(svc.DuplicateFeedName):
        await svc.create_feed(
            db_session,
            org_id=org.id,
            name="Dup",
            server_url=SERVER,
            collection_id=COLLECTION,
        )


@pytest.mark.asyncio
async def test_update_flipping_auth_style_revalidates_the_pair(db_session: AsyncSession):
    """none → bearer without supplying a reference must fail, not half-apply."""
    org = _make_org(db_session)
    await db_session.commit()

    row = await svc.create_feed(
        db_session,
        org_id=org.id,
        name="Flip",
        server_url=SERVER,
        collection_id=COLLECTION,
    )
    await db_session.commit()

    with pytest.raises(svc.InvalidFeedConfig):
        await svc.update_feed(
            db_session, org_id=org.id, feed_id=row.id, changes={"auth_style": "bearer"}
        )


# --------------------------------------------------------------------------- #
# Service — org scoping
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_feeds_are_org_scoped(db_session: AsyncSession):
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.commit()

    feed_a = await svc.create_feed(
        db_session, org_id=org_a.id, name="A feed", server_url=SERVER, collection_id=COLLECTION
    )
    await svc.create_feed(
        db_session, org_id=org_b.id, name="B feed", server_url=SERVER, collection_id=COLLECTION
    )
    await db_session.commit()

    assert [f.name for f in await svc.list_feeds(db_session, org_id=org_a.id)] == ["A feed"]
    assert [f.name for f in await svc.list_feeds(db_session, org_id=org_b.id)] == ["B feed"]
    # Org B cannot resolve org A's feed by id.
    assert await svc.get_feed(db_session, org_id=org_b.id, feed_id=feed_a.id) is None
    assert await svc.delete_feed(db_session, org_id=org_b.id, feed_id=feed_a.id) is False


@pytest.mark.asyncio
async def test_same_name_allowed_in_different_orgs(db_session: AsyncSession):
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.commit()

    await svc.create_feed(
        db_session, org_id=org_a.id, name="Shared", server_url=SERVER, collection_id=COLLECTION
    )
    await svc.create_feed(
        db_session, org_id=org_b.id, name="Shared", server_url=SERVER, collection_id=COLLECTION
    )
    await db_session.commit()

    assert len(await svc.list_feeds(db_session, org_id=org_a.id)) == 1
    assert len(await svc.list_feeds(db_session, org_id=org_b.id)) == 1


# --------------------------------------------------------------------------- #
# API — RBAC + round-trip
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_analyst_cannot_read_feeds(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    _, token = await _make_user(db_session, org_id=org.id, role="analyst")

    resp = await client.get("/api/v1/taxii/feeds", headers=auth_header(token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_senior_analyst_can_read_but_not_write(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    _, token = await _make_user(db_session, org_id=org.id, role="senior_analyst")

    assert (await client.get("/api/v1/taxii/feeds", headers=auth_header(token))).status_code == 200

    resp = await client.post(
        "/api/v1/taxii/feeds",
        headers=auth_header(token),
        json={"name": "Nope", "server_url": SERVER, "collection_id": COLLECTION},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_crud_round_trip(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    _, token = await _make_user(db_session, org_id=org.id, role="admin")

    created = await client.post(
        "/api/v1/taxii/feeds",
        headers=auth_header(token),
        json={
            "name": "Anomali",
            "server_url": SERVER,
            "collection_id": COLLECTION,
            "auth_style": "bearer",
            "auth_secret_ref": VALID_REF,
            "poll_interval_minutes": 30,
        },
    )
    assert created.status_code == 201, created.text
    feed_id = created.json()["id"]
    # The API echoes the reference (config), never resolved material.
    assert created.json()["auth_secret_ref"] == VALID_REF

    listed = await client.get("/api/v1/taxii/feeds", headers=auth_header(token))
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    patched = await client.patch(
        f"/api/v1/taxii/feeds/{feed_id}",
        headers=auth_header(token),
        json={"enabled": False, "poll_interval_minutes": 120},
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False
    assert patched.json()["poll_interval_minutes"] == 120

    assert (
        await client.delete(f"/api/v1/taxii/feeds/{feed_id}", headers=auth_header(token))
    ).status_code == 204
    assert (
        await client.get(f"/api/v1/taxii/feeds/{feed_id}", headers=auth_header(token))
    ).status_code == 404


@pytest.mark.asyncio
async def test_api_rejects_inline_secret_with_422(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    _, token = await _make_user(db_session, org_id=org.id, role="admin")

    resp = await client.post(
        "/api/v1/taxii/feeds",
        headers=auth_header(token),
        json={
            "name": "Inline",
            "server_url": SERVER,
            "collection_id": COLLECTION,
            "auth_style": "bearer",
            "auth_secret_ref": "raw-bearer-token-abcdef123456",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_api_cannot_read_another_orgs_feed(client: AsyncClient, db_session: AsyncSession):
    """Cross-tenant id resolution 404s, exactly like a nonexistent feed."""
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.commit()

    feed = await svc.create_feed(
        db_session, org_id=org_a.id, name="A only", server_url=SERVER, collection_id=COLLECTION
    )
    await db_session.commit()

    _, token_b = await _make_user(db_session, org_id=org_b.id, role="admin")
    resp = await client.get(f"/api/v1/taxii/feeds/{feed.id}", headers=auth_header(token_b))
    assert resp.status_code == 404

    resp = await client.patch(
        f"/api/v1/taxii/feeds/{feed.id}",
        headers=auth_header(token_b),
        json={"enabled": False},
    )
    assert resp.status_code == 404
