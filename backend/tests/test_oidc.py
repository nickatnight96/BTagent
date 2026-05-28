"""Tests for generic OIDC SSO (auth-code + PKCE) with JIT provisioning (#144, Phase 1b).

The IdP is mocked end-to-end: discovery, token, and JWKS are served by an
``httpx.MockTransport`` installed on ``oidc._http_transport`` so EVERY OIDC call
runs with NO live network (no new CI services). ID tokens are signed with a
locally-generated RSA key whose public half is published in the fake JWKS, so
real signature verification exercises the production path.

Coverage:
  * ``state`` mismatch → 400 (CSRF defence).
  * ``nonce`` mismatch → ID-token rejected (replay defence).
  * PKCE: the ``code_verifier`` from the stashed cookie is sent to the token
    endpoint and bound to the original challenge.
  * ID-token signature failure (wrong key) → rejected.
  * JIT provisioning: a fresh subject creates a ``UserRow`` + ``sso_identity``;
    a returning subject reuses the same user.
  * role mapping from the configured ``role_claim``.
  * REGRESSION: the default no-provider config boots, and an unknown provider
    → 404 (so existing login/UAT/E2E are unaffected).

Pattern mirrors test_mfa.py / test_cookie_auth.py: seed via the test session
factory, drive the FastAPI app through the httpx ASGI client (which carries the
signed-state cookie between the /login and /callback legs).
"""

from __future__ import annotations

import time

import httpx
import pytest
import pytest_asyncio
from authlib.jose import JsonWebKey, jwt
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select

from btagent_backend.auth import oidc
from btagent_backend.auth.cookies import ACCESS_COOKIE_NAME
from btagent_backend.config import OIDCProviderConfig, get_settings
from btagent_backend.db.models import SSOIdentityRow, UserRow

# ---------------------------------------------------------------------------
# Fake IdP constants
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.test.example"
_PROVIDER_KEY = "testidp"
_CLIENT_ID = "btagent-client"
_REDIRECT_URI = "http://testserver/api/v1/auth/sso/testidp/callback"
_AUTHORIZE_ENDPOINT = f"{_ISSUER}/authorize"
_TOKEN_ENDPOINT = f"{_ISSUER}/token"
_JWKS_URI = f"{_ISSUER}/jwks"

_LOGIN_PATH = f"/api/v1/auth/sso/{_PROVIDER_KEY}/login"
_CALLBACK_PATH = f"/api/v1/auth/sso/{_PROVIDER_KEY}/callback"

# A second RSA key NOT published in the JWKS — used to forge a token whose
# signature can't be verified against the IdP's keys.
_signing_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
_attacker_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)


def _public_jwks() -> dict:
    """The JWKS the fake IdP serves (public half of ``_signing_key`` only)."""
    return {"keys": [_signing_key.as_dict(is_private=False)]}


def _discovery_doc() -> dict:
    return {
        "issuer": _ISSUER,
        "authorization_endpoint": _AUTHORIZE_ENDPOINT,
        "token_endpoint": _TOKEN_ENDPOINT,
        "jwks_uri": _JWKS_URI,
    }


def _make_id_token(
    *,
    nonce: str,
    sub: str = "idp-sub-123",
    email: str | None = "alice@idp.test.example",
    email_verified: bool | None = True,
    groups: list[str] | None = None,
    key: JsonWebKey | None = None,
    aud: str = _CLIENT_ID,
    iss: str = _ISSUER,
) -> str:
    """Sign an RS256 ID token with the (default IdP) signing key.

    ``email_verified`` defaults to ``True`` (a correctly-configured IdP that
    has verified the address). Pass ``False`` to model an unverified email and
    ``None`` to omit the claim entirely.
    """
    signer = key if key is not None else _signing_key
    header = {"alg": "RS256", "kid": signer.as_dict(is_private=False).get("kid")}
    now = int(time.time())
    claims: dict = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "exp": now + 600,
        "iat": now,
        "nonce": nonce,
    }
    if email is not None:
        claims["email"] = email
    if email_verified is not None:
        claims["email_verified"] = email_verified
    if groups is not None:
        claims["groups"] = groups
    return jwt.encode(header, claims, signer).decode("ascii")


# ---------------------------------------------------------------------------
# MockTransport — the entire IdP
# ---------------------------------------------------------------------------


class _FakeIdP:
    """Captures token-endpoint form data and serves a configurable id_token."""

    def __init__(self) -> None:
        self.id_token: str | None = None
        self.token_form: dict[str, str] = {}
        self.token_status: int = 200
        self.discovery_doc: dict = _discovery_doc()

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.discovery_doc)
        if url == _JWKS_URI:
            return httpx.Response(200, json=_public_jwks())
        if url == _TOKEN_ENDPOINT:
            # Capture the posted form (PKCE verifier, code, etc.).
            body = request.content.decode("utf-8")
            self.token_form = dict(pair.split("=", 1) for pair in body.split("&") if "=" in pair)
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token, "token_type": "Bearer"})
        return httpx.Response(404, json={"error": "not_found"})


@pytest_asyncio.fixture()
async def idp():
    """Install the fake-IdP transport on the OIDC module for the test."""
    fake = _FakeIdP()
    oidc._http_transport = httpx.MockTransport(fake.handler)
    oidc._reset_for_tests()
    yield fake
    oidc._http_transport = None
    oidc._reset_for_tests()


@pytest_asyncio.fixture()
async def provider(idp):
    """Register the test provider in the (cached) settings for the test.

    Mutating the cached ``Settings.oidc_providers`` dict in place keeps the
    no-provider default for every other test (we pop the key on teardown).
    """
    settings = get_settings()
    settings.oidc_providers[_PROVIDER_KEY] = OIDCProviderConfig(
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        client_secret="test-client-secret",
        redirect_uri=_REDIRECT_URI,
        scopes=["openid", "email", "profile"],
        role_claim="groups",
        role_map={"soc-admins": "admin", "soc-seniors": "senior_analyst"},
        default_role="analyst",
    )
    yield settings.oidc_providers[_PROVIDER_KEY]
    settings.oidc_providers.pop(_PROVIDER_KEY, None)


async def _begin_login(client) -> tuple[str, str]:
    """Hit /login (no-follow), returning the IdP-bound ``state`` and ``nonce``.

    The signed-state cookie is captured into the client's jar automatically.
    """
    resp = await client.get(_LOGIN_PATH, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(_AUTHORIZE_ENDPOINT)
    assert "code_challenge=" in location and "code_challenge_method=S256" in location
    from urllib.parse import parse_qs, urlsplit

    qs = parse_qs(urlsplit(location).query)
    return qs["state"][0], qs["nonce"][0]


# ---------------------------------------------------------------------------
# Unit-level: oidc.py protocol helpers
# ---------------------------------------------------------------------------


def test_pkce_challenge_is_s256_of_verifier():
    """PKCE S256 challenge matches the documented base64url(sha256(verifier))."""
    import base64
    import hashlib

    verifier = oidc.generate_pkce_verifier()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert oidc.pkce_challenge(verifier) == expected
    # 43..128 unreserved chars (RFC 7636).
    assert 43 <= len(verifier) <= 128


def test_map_role_from_claim_and_fallback():
    """role_map first-match wins; unknown/absent claim → default_role."""
    cfg = OIDCProviderConfig(
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        client_secret="x",
        redirect_uri=_REDIRECT_URI,
        role_claim="groups",
        role_map={"soc-admins": "admin"},
        default_role="analyst",
    )
    assert oidc.map_role(cfg, {"groups": ["nope", "soc-admins"]}) == "admin"
    assert oidc.map_role(cfg, {"groups": ["unmapped"]}) == "analyst"
    assert oidc.map_role(cfg, {}) == "analyst"
    # A role_map value that is not a real UserRole can never be granted.
    cfg.role_map = {"soc-admins": "superuser-not-a-role"}
    assert oidc.map_role(cfg, {"groups": ["soc-admins"]}) == "analyst"


@pytest.mark.asyncio
async def test_verify_id_token_nonce_mismatch_rejected(provider, idp):
    """A valid signature but wrong nonce → OIDCError (replay defence)."""
    discovery = await oidc.discover(provider)
    token = _make_id_token(nonce="the-real-nonce")
    with pytest.raises(oidc.OIDCError):
        await oidc.verify_id_token(
            provider, discovery, id_token=token, expected_nonce="a-different-nonce"
        )


@pytest.mark.asyncio
async def test_verify_id_token_bad_signature_rejected(provider, idp):
    """An ID token signed with a key NOT in the JWKS → OIDCError."""
    discovery = await oidc.discover(provider)
    forged = _make_id_token(nonce="n", key=_attacker_key)
    with pytest.raises(oidc.OIDCError):
        await oidc.verify_id_token(provider, discovery, id_token=forged, expected_nonce="n")


@pytest.mark.asyncio
async def test_verify_id_token_wrong_aud_rejected(provider, idp):
    """An ID token whose ``aud`` is not our client_id → OIDCError."""
    discovery = await oidc.discover(provider)
    token = _make_id_token(nonce="n", aud="some-other-client")
    with pytest.raises(oidc.OIDCError):
        await oidc.verify_id_token(provider, discovery, id_token=token, expected_nonce="n")


# ---------------------------------------------------------------------------
# HTTP-level: login + callback through the FastAPI app
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_callback_state_mismatch_rejected(provider, idp, client):
    """A callback ``state`` that doesn't match the stashed one → 400 (CSRF)."""
    await _begin_login(client)
    resp = await client.get(
        _CALLBACK_PATH,
        params={"code": "auth-code", "state": "attacker-supplied-state"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_callback_missing_state_cookie_rejected(provider, idp, client):
    """Without the signed-state cookie the callback cannot proceed → 400."""
    resp = await client.get(
        _CALLBACK_PATH,
        params={"code": "auth-code", "state": "whatever"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_callback_pkce_verifier_sent_and_jit_provision(provider, idp, client, db_session):
    """Happy path: PKCE verifier is sent, and JIT creates user + sso_identity."""
    state, nonce = await _begin_login(client)
    idp.id_token = _make_id_token(nonce=nonce, sub="sub-new-user", email="new@idp.test.example")

    resp = await client.get(
        _CALLBACK_PATH,
        params={"code": "auth-code", "state": state},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    # Session established via the standard auth-cookie path.
    assert ACCESS_COOKIE_NAME in resp.cookies

    # PKCE: the token endpoint received a code_verifier (S256 enforcement).
    assert idp.token_form.get("code_verifier"), "PKCE code_verifier not sent to token endpoint"
    assert idp.token_form.get("grant_type") == "authorization_code"
    assert idp.token_form.get("code") == "auth-code"

    # JIT: a fresh user + linked sso_identity exist.
    ident = (
        await db_session.execute(
            select(SSOIdentityRow).where(
                SSOIdentityRow.provider == _PROVIDER_KEY,
                SSOIdentityRow.subject == "sub-new-user",
            )
        )
    ).scalar_one_or_none()
    assert ident is not None
    user = await db_session.get(UserRow, ident.user_id)
    assert user is not None
    assert user.email == "new@idp.test.example"
    # No role claim → default_role.
    assert user.role == "analyst"
    # SSO-only user: no local password credential.
    assert user.password_hash is None


@pytest.mark.asyncio
async def test_callback_role_mapping_from_claim(provider, idp, client, db_session):
    """A mapped group claim provisions the user with the mapped role."""
    state, nonce = await _begin_login(client)
    idp.id_token = _make_id_token(
        nonce=nonce,
        sub="sub-admin-user",
        email="admin@idp.test.example",
        groups=["soc-admins"],
    )
    resp = await client.get(
        _CALLBACK_PATH, params={"code": "c", "state": state}, follow_redirects=False
    )
    assert resp.status_code == 302

    ident = (
        await db_session.execute(
            select(SSOIdentityRow).where(SSOIdentityRow.subject == "sub-admin-user")
        )
    ).scalar_one_or_none()
    assert ident is not None
    user = await db_session.get(UserRow, ident.user_id)
    assert user is not None and user.role == "admin"


@pytest.mark.asyncio
async def test_callback_nonce_mismatch_rejected_end_to_end(provider, idp, client):
    """An ID token whose nonce ≠ the stashed nonce → 400 at the callback."""
    state, _nonce = await _begin_login(client)
    idp.id_token = _make_id_token(nonce="not-the-stashed-nonce", sub="sub-replay")
    resp = await client.get(
        _CALLBACK_PATH, params={"code": "c", "state": state}, follow_redirects=False
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_callback_returning_user_reuses_identity(provider, idp, client, db_session):
    """A second login for the same subject reuses the same user (no dup)."""
    # First login → creates the user.
    state1, nonce1 = await _begin_login(client)
    idp.id_token = _make_id_token(nonce=nonce1, sub="sub-repeat", email="repeat@idp.test.example")
    r1 = await client.get(
        _CALLBACK_PATH, params={"code": "c1", "state": state1}, follow_redirects=False
    )
    assert r1.status_code == 302

    first_user_id = (
        await db_session.execute(
            select(SSOIdentityRow.user_id).where(SSOIdentityRow.subject == "sub-repeat")
        )
    ).scalar_one()

    # Second login, same subject → same user, still exactly one identity row.
    state2, nonce2 = await _begin_login(client)
    idp.id_token = _make_id_token(nonce=nonce2, sub="sub-repeat", email="repeat@idp.test.example")
    r2 = await client.get(
        _CALLBACK_PATH, params={"code": "c2", "state": state2}, follow_redirects=False
    )
    assert r2.status_code == 302

    rows = (
        (
            await db_session.execute(
                select(SSOIdentityRow).where(SSOIdentityRow.subject == "sub-repeat")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].user_id == first_user_id


# ---------------------------------------------------------------------------
# SECURITY: verified-email gating + no silent password-account linking (#144)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_callback_unverified_email_refused(provider, idp, client, db_session):
    """(a) An unverified-email claim → login refused; nothing created/linked.

    Closes the takeover vector where an IdP asserts ``email=victim@corp.com``
    without having verified it.
    """
    state, nonce = await _begin_login(client)
    idp.id_token = _make_id_token(
        nonce=nonce,
        sub="sub-unverified",
        email="unverified@idp.test.example",
        email_verified=False,
    )
    resp = await client.get(
        _CALLBACK_PATH, params={"code": "c", "state": state}, follow_redirects=False
    )
    assert resp.status_code == 400
    assert ACCESS_COOKIE_NAME not in resp.cookies

    # No user with that email, and no identity for that subject, were created.
    user = (
        await db_session.execute(
            select(UserRow).where(UserRow.email == "unverified@idp.test.example")
        )
    ).scalar_one_or_none()
    assert user is None
    ident = (
        await db_session.execute(
            select(SSOIdentityRow).where(SSOIdentityRow.subject == "sub-unverified")
        )
    ).scalar_one_or_none()
    assert ident is None


@pytest.mark.asyncio
async def test_callback_verified_email_matches_password_user_conflict(
    provider, idp, client, db_session
):
    """(b) Verified email matching an existing PASSWORD user → 409, no link.

    The high-value local-credential account must not be auto-bound to SSO.
    """
    from btagent_backend.auth.jwt import hash_password
    from btagent_backend.db.models import DEFAULT_ORG_ID

    victim = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username="victim-local",
        email="victim@corp.com",
        password_hash=hash_password("Victim-P@ss-123!"),
        role="incident_commander",
    )
    db_session.add(victim)
    await db_session.commit()

    state, nonce = await _begin_login(client)
    idp.id_token = _make_id_token(
        nonce=nonce,
        sub="sub-attacker",
        email="victim@corp.com",
        email_verified=True,
    )
    resp = await client.get(
        _CALLBACK_PATH, params={"code": "c", "state": state}, follow_redirects=False
    )
    assert resp.status_code == 409
    assert ACCESS_COOKIE_NAME not in resp.cookies

    # No sso_identity was linked to the victim (or anyone) for that subject.
    ident = (
        await db_session.execute(
            select(SSOIdentityRow).where(SSOIdentityRow.subject == "sub-attacker")
        )
    ).scalar_one_or_none()
    assert ident is None
    # The victim account is untouched (still password-backed).
    refreshed = await db_session.get(UserRow, victim.id)
    assert refreshed is not None and refreshed.password_hash is not None


@pytest.mark.asyncio
async def test_callback_verified_email_matches_sso_only_user_links(
    provider, idp, client, db_session
):
    """(c) Verified email matching an existing SSO-ONLY user → links correctly."""
    from btagent_backend.db.models import DEFAULT_ORG_ID

    sso_only = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username="sso-only-existing",
        email="ssoonly@idp.test.example",
        password_hash=None,  # SSO-only: no local credential
        role="analyst",
    )
    db_session.add(sso_only)
    await db_session.commit()

    state, nonce = await _begin_login(client)
    idp.id_token = _make_id_token(
        nonce=nonce,
        sub="sub-sso-link",
        email="ssoonly@idp.test.example",
        email_verified=True,
    )
    resp = await client.get(
        _CALLBACK_PATH, params={"code": "c", "state": state}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert ACCESS_COOKIE_NAME in resp.cookies

    # The identity links to the EXISTING sso-only user (no duplicate created).
    ident = (
        await db_session.execute(
            select(SSOIdentityRow).where(SSOIdentityRow.subject == "sub-sso-link")
        )
    ).scalar_one_or_none()
    assert ident is not None
    assert ident.user_id == sso_only.id
    matches = (
        (
            await db_session.execute(
                select(UserRow).where(UserRow.email == "ssoonly@idp.test.example")
            )
        )
        .scalars()
        .all()
    )
    assert len(matches) == 1


@pytest.mark.asyncio
async def test_callback_verified_email_brand_new_creates_user(provider, idp, client, db_session):
    """(d) Verified email, brand-new subject/email → creates a password-less user."""
    state, nonce = await _begin_login(client)
    idp.id_token = _make_id_token(
        nonce=nonce,
        sub="sub-brand-new",
        email="brandnew@idp.test.example",
        email_verified=True,
    )
    resp = await client.get(
        _CALLBACK_PATH, params={"code": "c", "state": state}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert ACCESS_COOKIE_NAME in resp.cookies

    ident = (
        await db_session.execute(
            select(SSOIdentityRow).where(SSOIdentityRow.subject == "sub-brand-new")
        )
    ).scalar_one_or_none()
    assert ident is not None
    user = await db_session.get(UserRow, ident.user_id)
    assert user is not None
    assert user.email == "brandnew@idp.test.example"
    assert user.password_hash is None  # SSO-only, as before
    assert user.role == "analyst"  # no group claim → default_role


@pytest.mark.asyncio
async def test_callback_idp_error_rejected(provider, idp, client):
    """An IdP error response (e.g. consent denied) → 400."""
    await _begin_login(client)
    resp = await client.get(
        _CALLBACK_PATH, params={"error": "access_denied"}, follow_redirects=False
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# REGRESSION: default no-provider config + unknown provider
# ---------------------------------------------------------------------------


def test_default_config_has_no_providers_and_boots():
    """The default settings carry NO OIDC providers (CI safety)."""
    # NOTE: deliberately does not use the ``provider`` fixture, so the registry
    # is the untouched default.
    assert get_settings().oidc_providers == {}
    # The app module is importable with no provider configured.
    import btagent_backend.main  # noqa: F401


@pytest.mark.asyncio
async def test_unknown_provider_login_404(client):
    """An unknown/unconfigured provider key → 404 on /login."""
    resp = await client.get("/api/v1/auth/sso/does-not-exist/login", follow_redirects=False)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unknown_provider_callback_404(client):
    """An unknown/unconfigured provider key → 404 on /callback."""
    resp = await client.get(
        "/api/v1/auth/sso/does-not-exist/callback",
        params={"code": "c", "state": "s"},
        follow_redirects=False,
    )
    assert resp.status_code == 404
