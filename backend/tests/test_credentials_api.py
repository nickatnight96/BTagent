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


@pytest_asyncio.fixture()
async def senior_token(db_session: AsyncSession) -> str:
    """A senior_analyst — has ``credential:view`` but not ``credential:manage``.

    Distinct from ``analyst_token``: an analyst is denied everything here, so
    it can't show that *verify* specifically sits behind the manage gate
    rather than the view gate.
    """
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"credsenior_{generate_id('n')[-6:]}",
        email=f"credsenior_{generate_id('n')[-6:]}@btagent.test",
        password_hash=hash_password("Senior-P@ss-123!"),
        role="senior_analyst",
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


# --------------------------------------------------------------------------- #
# Reference verification (#101) — POST /credentials/{connector}/verify
# --------------------------------------------------------------------------- #


async def test_verify_reports_resolved_for_a_set_env_var(client, admin_token, monkeypatch) -> None:
    monkeypatch.setenv("BTAGENT_VERIFY_OK", "a-real-token")
    await client.put(
        "/api/v1/credentials/splunk",
        headers=auth_header(admin_token),
        json={"secret_ref": "${env:BTAGENT_VERIFY_OK}"},
    )

    resp = await client.post("/api/v1/credentials/splunk/verify", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["bound"] is True
    assert body["resolved"] is True
    assert body["provider"] == "env"


async def test_verify_catches_a_typod_env_reference(client, admin_token, monkeypatch) -> None:
    """The whole point: a missing env var resolves to "" and is otherwise silent."""
    monkeypatch.delenv("BTAGENT_VERIFY_TYPO", raising=False)
    await client.put(
        "/api/v1/credentials/splunk",
        headers=auth_header(admin_token),
        json={"secret_ref": "${env:BTAGENT_VERIFY_TYPO}"},
    )

    resp = await client.post("/api/v1/credentials/splunk/verify", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["bound"] is True
    assert body["resolved"] is False
    assert "empty" in body["detail"].lower()


async def test_verify_treats_the_nonprod_placeholder_as_unresolved(
    client, admin_token, monkeypatch
) -> None:
    """A vault ref with no client resolves to '<unresolved:...>' outside prod.

    That string is truthy, so a naive check would call a broken Vault binding
    healthy in every dev/staging deployment — the exact false-negative this
    endpoint exists to prevent.
    """
    monkeypatch.delenv("CROWDSTRIKE_API_KEY", raising=False)
    await client.put(
        "/api/v1/credentials/crowdstrike",
        headers=auth_header(admin_token),
        json={"secret_ref": "${secret:vault:crowdstrike/api_key}"},
    )

    resp = await client.post(
        "/api/v1/credentials/crowdstrike/verify", headers=auth_header(admin_token)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resolved"] is False
    assert body["provider"] == "vault"
    assert "placeholder" in body["detail"].lower()


async def test_verify_reports_unbound_rather_than_404(client, admin_token) -> None:
    """An unbound connector is a legitimate answer, not an error."""
    await client.delete("/api/v1/credentials/elastic", headers=auth_header(admin_token))
    resp = await client.post("/api/v1/credentials/elastic/verify", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["bound"] is False
    assert body["resolved"] is False
    assert body["secret_ref"] == ""


async def test_verify_unknown_connector_404(client, admin_token) -> None:
    resp = await client.post(
        "/api/v1/credentials/not_a_connector/verify", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


async def test_verify_never_returns_the_resolved_value(client, admin_token, monkeypatch) -> None:
    """The response must not carry the credential, in any field."""
    secret = "super-secret-material-9f3a"
    monkeypatch.setenv("BTAGENT_VERIFY_LEAK", secret)
    await client.put(
        "/api/v1/credentials/splunk",
        headers=auth_header(admin_token),
        json={"secret_ref": "${env:BTAGENT_VERIFY_LEAK}"},
    )

    resp = await client.post("/api/v1/credentials/splunk/verify", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert secret not in resp.text
    # No length either — that is an entropy hint the operator never needs.
    assert str(len(secret)) not in str(resp.json().get("detail", ""))


async def test_verify_takes_no_body_so_it_cannot_probe_arbitrary_refs(
    client, admin_token, monkeypatch
) -> None:
    """A caller-supplied reference must not be honoured.

    Otherwise the endpoint answers hit/miss for any env var or Vault path an
    admin cares to guess, turning a diagnostic into a discovery tool. The
    route resolves only what is already bound, so a body is inert.
    """
    monkeypatch.setenv("BTAGENT_VERIFY_OTHER", "value-of-an-unrelated-secret")
    monkeypatch.delenv("BTAGENT_VERIFY_BOUND", raising=False)
    await client.put(
        "/api/v1/credentials/splunk",
        headers=auth_header(admin_token),
        json={"secret_ref": "${env:BTAGENT_VERIFY_BOUND}"},
    )

    resp = await client.post(
        "/api/v1/credentials/splunk/verify",
        headers=auth_header(admin_token),
        json={"secret_ref": "${env:BTAGENT_VERIFY_OTHER}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The bound (missing) ref is what got checked — not the one in the body.
    assert body["secret_ref"] == "${env:BTAGENT_VERIFY_BOUND}"
    assert body["resolved"] is False


async def test_verify_requires_admin(client, senior_token) -> None:
    """Reading the secret backend is a privileged diagnostic, not a view."""
    resp = await client.post("/api/v1/credentials/splunk/verify", headers=auth_header(senior_token))
    assert resp.status_code == 403
