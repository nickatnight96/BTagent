"""Tests for the SAML 2.0 SSO routes (#170, Phase 2).

Mirrors the two-layer split of ``test_saml.py``:

* **Layer A** (no xmlsec) — provider 404s, the missing-SAMLResponse / missing-
  state / RelayState-mismatch 400s, and the 503 path when the ``backend[saml]``
  extra is absent (simulated by monkeypatching the lazy loader).
* **Layer B** (``requires_pysaml2``) — the full ``/login`` → IdP → ``/acs``
  round-trip through the FastAPI app: a real signed assertion mints a session
  (auth cookies + 302 to the frontend) and creates the ``sso_identity`` row.

The fake IdP + constants are reused from ``test_saml.py``.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient
from jose import jwt
from sqlalchemy import delete, select

from btagent_backend.auth import saml as saml_lib
from btagent_backend.config import SAMLProviderConfig, get_settings
from btagent_backend.db.models import SSOIdentityRow
from tests.test_saml import ACS, IDP_ENTITY, SP_ENTITY, SSO_URL, _TestIdP, requires_pysaml2

PROVIDER = "test"  # ACS path is /api/v1/auth/saml/test/acs (must match config.acs_url)
LOGIN_URL = f"/api/v1/auth/saml/{PROVIDER}/login"
ACS_URL = f"/api/v1/auth/saml/{PROVIDER}/acs"
METADATA_URL = f"/api/v1/auth/saml/{PROVIDER}/metadata"


@pytest_asyncio.fixture(autouse=True)
async def _isolate(db_session):
    """Clear sso_identity + the metadata cache around each test."""
    await db_session.execute(delete(SSOIdentityRow))
    await db_session.commit()
    saml_lib._reset_for_tests()
    yield
    await db_session.execute(delete(SSOIdentityRow))
    await db_session.commit()


def _register_provider(cfg: SAMLProviderConfig):
    get_settings().saml_providers[PROVIDER] = cfg


@pytest_asyncio.fixture()
async def basic_provider():
    """A configured (manual) provider with a dummy cert — for 404/400/503 paths."""
    cfg = SAMLProviderConfig(
        idp_entity_id=IDP_ENTITY,
        sso_url=SSO_URL,
        x509cert="-----BEGIN CERTIFICATE-----\nAAAB\n-----END CERTIFICATE-----",
        sp_entity_id=SP_ENTITY,
        acs_url=ACS,
        role_attr="Role",
        role_map={"soc-admins": "admin"},
    )
    _register_provider(cfg)
    yield cfg
    get_settings().saml_providers.pop(PROVIDER, None)


# --- Layer A: routing / validation, no pysaml2 needed ---------------------- #


async def test_login_unknown_provider_404(client: AsyncClient):
    resp = await client.get("/api/v1/auth/saml/nope/login")
    assert resp.status_code == 404


async def test_acs_unknown_provider_404(client: AsyncClient):
    resp = await client.post("/api/v1/auth/saml/nope/acs", data={"SAMLResponse": "x"})
    assert resp.status_code == 404


async def test_metadata_unknown_provider_404(client: AsyncClient):
    resp = await client.get("/api/v1/auth/saml/nope/metadata")
    assert resp.status_code == 404


async def test_acs_missing_response_400(client: AsyncClient, basic_provider):
    resp = await client.post(ACS_URL, data={"RelayState": "x"})
    assert resp.status_code == 400


async def test_acs_missing_state_cookie_400(client: AsyncClient, basic_provider):
    # SAMLResponse present, but no state cookie was ever set → reject.
    resp = await client.post(ACS_URL, data={"SAMLResponse": "x", "RelayState": "y"})
    assert resp.status_code == 400


async def test_login_503_when_extra_missing(client: AsyncClient, basic_provider, monkeypatch):
    """If pysaml2 isn't installed, the SAML routes return 503 (not 500)."""

    def boom() -> None:
        raise saml_lib.SAMLNotInstalledError("no extra")

    monkeypatch.setattr(saml_lib, "_load_saml", boom)
    resp = await client.get(LOGIN_URL)
    assert resp.status_code == 503


async def test_metadata_503_when_extra_missing(client: AsyncClient, basic_provider, monkeypatch):
    def boom() -> None:
        raise saml_lib.SAMLNotInstalledError("no extra")

    monkeypatch.setattr(saml_lib, "_load_saml", boom)
    resp = await client.get(METADATA_URL)
    assert resp.status_code == 503


# --- Layer B: full login → ACS round-trip (requires the extra) ------------- #


@pytest_asyncio.fixture()
async def live_provider(idp_server: _TestIdP):
    cfg = SAMLProviderConfig(
        idp_entity_id=IDP_ENTITY,
        sso_url=SSO_URL,
        x509cert=idp_server.cert_pem,
        sp_entity_id=SP_ENTITY,
        acs_url=ACS,
        role_attr="Role",
        role_map={"soc-admins": "admin"},
        email_attr="mail",
    )
    _register_provider(cfg)
    yield cfg
    get_settings().saml_providers.pop(PROVIDER, None)


@pytest.fixture(scope="module")
def idp_server():
    return _TestIdP()


@requires_pysaml2
async def test_metadata_returns_sp_xml(client: AsyncClient, live_provider):
    resp = await client.get(METADATA_URL)
    assert resp.status_code == 200
    assert "samlmetadata+xml" in resp.headers["content-type"]
    assert SP_ENTITY in resp.text and "AssertionConsumerService" in resp.text


@requires_pysaml2
async def test_login_redirects_to_idp_and_sets_state_cookie(client: AsyncClient, live_provider):
    resp = await client.get(LOGIN_URL)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith(SSO_URL)
    assert "btagent_saml_state" in resp.headers.get("set-cookie", "")


@requires_pysaml2
async def test_full_login_acs_mints_session_and_links_identity(
    client: AsyncClient, live_provider, idp_server, db_session
):
    # 1) /login → grab the signed-state cookie and decode the AuthnRequest id.
    login = await client.get(LOGIN_URL)
    assert login.status_code == 302
    state_cookie = client.cookies.get("btagent_saml_state")
    assert state_cookie
    settings = get_settings()
    stash = jwt.decode(state_cookie, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    request_id, relay = stash["rid"], stash["relay"]

    # 2) IdP mints a signed Response answering our AuthnRequest.
    saml_response = idp_server.make_response(
        request_id, email="dana@corp.test", roles=("soc-admins",)
    )

    # 3) POST it to the ACS (the state cookie rides along from the jar).
    acs = await client.post(
        ACS_URL,
        data={"SAMLResponse": saml_response, "RelayState": relay},
    )
    assert acs.status_code == 302, acs.text
    assert acs.headers["location"] == settings.frontend_url
    set_cookie = acs.headers.get("set-cookie", "")
    assert "btagent_access" in set_cookie  # a session was minted

    # 4) A saml sso_identity row now links the JIT-provisioned user.
    row = (
        await db_session.execute(
            select(SSOIdentityRow).where(
                SSOIdentityRow.provider == "saml", SSOIdentityRow.subject == "dana@corp.test"
            )
        )
    ).scalar_one_or_none()
    assert row is not None
    assert row.email == "dana@corp.test"


@requires_pysaml2
async def test_acs_relaystate_mismatch_rejected(client: AsyncClient, live_provider, idp_server):
    login = await client.get(LOGIN_URL)
    state_cookie = client.cookies.get("btagent_saml_state")
    settings = get_settings()
    stash = jwt.decode(state_cookie, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    saml_response = idp_server.make_response(stash["rid"], email="eve@corp.test")
    # Wrong RelayState → CSRF guard fires before any assertion processing.
    resp = await client.post(
        ACS_URL, data={"SAMLResponse": saml_response, "RelayState": "tampered"}
    )
    assert resp.status_code == 400
