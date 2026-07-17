"""Tests for the connector credential-reference API (#100).

The store holds ``${secret:...}`` references only — never raw material.
Covers the reference-validation invariant, unknown-connector rejection,
upsert/get/list/delete round-trips, and RBAC (view = senior_analyst,
manage = admin).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from btagent_shared.utils.secrets import is_secret_reference
from conftest import auth_header
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, UserRow
from btagent_backend.services import connector_credential_service as svc

VALID_REF = "${secret:vault:crowdstrike/api_key}"


# --------------------------------------------------------------------------- #
# Reference validation (pure)
# --------------------------------------------------------------------------- #


def test_is_secret_reference_accepts_single_reference() -> None:
    assert is_secret_reference("${secret:vault:okta/token}")
    assert is_secret_reference("${secret:aws:prod-key#field}")
    assert is_secret_reference("${env:BTAGENT_OKTA_TOKEN}")
    assert is_secret_reference("  ${env:X}  ")  # trimmed


def test_is_secret_reference_rejects_raw_and_mixed() -> None:
    assert not is_secret_reference("sk-live-rawsecretmaterial")
    assert not is_secret_reference("prefix ${env:X} suffix")
    assert not is_secret_reference("")
    assert not is_secret_reference("${env:X}${env:Y}")


# --------------------------------------------------------------------------- #
# Service invariants
# --------------------------------------------------------------------------- #


async def test_service_rejects_raw_material(db_session: AsyncSession) -> None:
    import pytest

    with pytest.raises(svc.InvalidCredentialReference):
        await svc.upsert_credential(
            db_session,
            org_id=DEFAULT_ORG_ID,
            connector_name="crowdstrike",
            secret_ref="raw-secret-not-a-reference",
        )


async def test_service_rejects_unknown_connector(db_session: AsyncSession) -> None:
    import pytest

    with pytest.raises(svc.UnknownConnector):
        await svc.upsert_credential(
            db_session,
            org_id=DEFAULT_ORG_ID,
            connector_name="not_a_connector",
            secret_ref=VALID_REF,
        )


async def test_service_upsert_replaces(db_session: AsyncSession) -> None:
    first = await svc.upsert_credential(
        db_session,
        org_id=DEFAULT_ORG_ID,
        connector_name="splunk",
        secret_ref="${env:SPLUNK_A}",
        label="first",
    )
    await db_session.commit()
    second = await svc.upsert_credential(
        db_session,
        org_id=DEFAULT_ORG_ID,
        connector_name="splunk",
        secret_ref="${env:SPLUNK_B}",
        label="second",
    )
    await db_session.commit()
    assert first.id == second.id  # same row, upserted
    assert second.secret_ref == "${env:SPLUNK_B}"
    assert second.label == "second"


# --------------------------------------------------------------------------- #
# Admin fixture
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def admin_token(db_session: AsyncSession) -> str:
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"credadmin_{generate_id('n')[-6:]}",
        email=f"credadmin_{generate_id('n')[-6:]}@btagent.test",
        password_hash=hash_password("Admin-P@ss-123!"),
        role="admin",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return create_token_pair(user.id, user.username, user.role).access_token


# --------------------------------------------------------------------------- #
# Endpoint: bind / read / list / delete
# --------------------------------------------------------------------------- #


async def test_bind_read_and_list(client, admin_token) -> None:
    resp = await client.put(
        "/api/v1/credentials/crowdstrike",
        headers=auth_header(admin_token),
        json={"secret_ref": VALID_REF, "label": "prod key"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["connector_name"] == "crowdstrike"
    assert body["secret_ref"] == VALID_REF
    assert body["label"] == "prod key"

    got = await client.get("/api/v1/credentials/crowdstrike", headers=auth_header(admin_token))
    assert got.status_code == 200
    assert got.json()["secret_ref"] == VALID_REF

    listed = await client.get("/api/v1/credentials", headers=auth_header(admin_token))
    assert listed.status_code == 200
    names = {c["connector_name"] for c in listed.json()["items"]}
    assert "crowdstrike" in names


async def test_bind_rejects_raw_material_422(client, admin_token) -> None:
    resp = await client.put(
        "/api/v1/credentials/crowdstrike",
        headers=auth_header(admin_token),
        json={"secret_ref": "raw-secret"},
    )
    assert resp.status_code == 422


async def test_bind_unknown_connector_404(client, admin_token) -> None:
    resp = await client.put(
        "/api/v1/credentials/not_a_connector",
        headers=auth_header(admin_token),
        json={"secret_ref": VALID_REF},
    )
    assert resp.status_code == 404


async def test_get_missing_binding_404(client, admin_token) -> None:
    resp = await client.get("/api/v1/credentials/elastic", headers=auth_header(admin_token))
    assert resp.status_code == 404


async def test_delete_binding(client, admin_token) -> None:
    await client.put(
        "/api/v1/credentials/sentinel",
        headers=auth_header(admin_token),
        json={"secret_ref": "${env:SENTINEL_KEY}"},
    )
    deleted = await client.delete("/api/v1/credentials/sentinel", headers=auth_header(admin_token))
    assert deleted.status_code == 204
    # Second delete is a 404 — nothing bound anymore.
    again = await client.delete("/api/v1/credentials/sentinel", headers=auth_header(admin_token))
    assert again.status_code == 404


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #


async def test_analyst_cannot_view_or_manage(client, analyst_token) -> None:
    # view requires senior_analyst
    assert (
        await client.get("/api/v1/credentials", headers=auth_header(analyst_token))
    ).status_code == 403
    # manage requires admin
    assert (
        await client.put(
            "/api/v1/credentials/crowdstrike",
            headers=auth_header(analyst_token),
            json={"secret_ref": VALID_REF},
        )
    ).status_code == 403


async def test_requires_auth(client) -> None:
    assert (await client.get("/api/v1/credentials")).status_code == 401
