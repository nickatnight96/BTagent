"""Generic OIDC SSO endpoints (#144, Phase 1b).

Two endpoints under ``/auth/sso/{provider}``, both UN-authed (the user has no
session yet) and public (auth is per-route in this codebase, so they are not
gated by ``get_current_user``):

* ``GET /auth/sso/{provider}/login`` — generate ``state`` + ``nonce`` + PKCE
  verifier, stash them server-side in a signed short-TTL httpOnly cookie, then
  302 to the IdP authorize URL. 404 for an unknown/unconfigured provider.
* ``GET /auth/sso/{provider}/callback`` — validate ``state`` (CSRF) + ``nonce``
  (replay), exchange the code (with the PKCE verifier), verify the ID-token
  signature + claims, then JIT-provision the user and link an
  ``sso_identity`` row. Finally mint a normal session pair via
  ``create_token_pair`` + ``set_auth_cookies`` and 302 to the frontend.

Why this is safe by construction:
  * SSO-issued tokens flow through the SAME ``create_token_pair`` /
    ``set_auth_cookies`` as password login, so revocation, refresh-rotation,
    and ``org_id`` scoping all apply unchanged.
  * SSO users authenticate at the IdP — they are NOT routed through the local
    MFA challenge.
  * The ``state``/``nonce``/PKCE-verifier never leave the browser as readable
    values: they live inside a signed (JWT, ``type="sso_state"``), httpOnly,
    SameSite=Lax, short-TTL cookie scoped to the SSO callback path.

Stash design (signed cookie, not Redis): the transient login parameters are
packed into a short-lived JWT signed with the app's ``jwt_secret`` and set as
an httpOnly cookie. This is tamper-proof (signature), confidential to JS
(httpOnly), bounded (TTL), and stateless (no Redis dependency on the login
leg). The callback decodes + verifies it, checks the ``provider`` matches, and
compares ``state``. SameSite=Lax lets the cookie ride the top-level redirect
back from the IdP.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import get_db
from btagent_backend.auth import oidc
from btagent_backend.auth.cookies import _is_secure, set_auth_cookies
from btagent_backend.auth.jwt import create_token_pair
from btagent_backend.config import OIDCProviderConfig, get_settings
from btagent_backend.db.models import SSOIdentityRow, UserRow

logger = logging.getLogger("btagent.auth.sso")

router = APIRouter(prefix="/auth/sso", tags=["auth", "sso"])

# Signed-state cookie. Carries the JWT that holds state/nonce/PKCE-verifier.
# Scoped to the SSO subtree + SameSite=Lax so it survives the top-level
# redirect back from the IdP but is never sent cross-site by a malicious page.
SSO_STATE_COOKIE_NAME = "btagent_sso_state"
SSO_STATE_COOKIE_PATH = "/api/v1/auth/sso"
# The login → callback round-trip (user logs in at the IdP) must finish inside
# this window. 10 minutes is generous for an interactive IdP login.
SSO_STATE_TTL_SECONDS = 600


def _get_provider(provider: str) -> OIDCProviderConfig:
    """Resolve a configured provider or raise 404.

    CI safety: with no providers configured (the default), EVERY provider key
    is unknown, so this 404s and the SSO routes are effectively inert — the
    rest of the app (and the test suite) is unaffected.
    """
    providers = get_settings().oidc_providers
    config = providers.get(provider)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown SSO provider")
    return config


def _sign_state(provider: str, state: str, nonce: str, code_verifier: str) -> str:
    """Pack the transient login params into a short-TTL signed JWT."""
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "type": "sso_state",
        "provider": provider,
        "state": state,
        "nonce": nonce,
        "cv": code_verifier,
        "exp": now + timedelta(seconds=SSO_STATE_TTL_SECONDS),
        "iat": int(now.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _decode_state(token: str) -> dict:
    """Decode + verify the signed-state JWT. Raises ``JWTError`` on failure."""
    settings = get_settings()
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != "sso_state":
        raise JWTError("not an sso_state token")
    return payload


@router.get("/{provider}/login")
async def sso_login(provider: str, response: Response):
    """Begin an OIDC SSO login: 302 to the IdP authorize URL.

    Generates ``state`` + ``nonce`` + PKCE verifier, stashes them in the signed
    httpOnly state cookie, and redirects the browser to the IdP.
    """
    config = _get_provider(provider)

    try:
        discovery = await oidc.discover(config)
    except oidc.OIDCError as exc:
        logger.warning("SSO discovery failed for provider=%s: %s", provider, exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SSO discovery failed")

    state = oidc.generate_state()
    nonce = oidc.generate_nonce()
    verifier = oidc.generate_pkce_verifier()
    challenge = oidc.pkce_challenge(verifier)

    authorize_url = oidc.build_authorize_url(
        config,
        discovery,
        state=state,
        nonce=nonce,
        code_challenge=challenge,
    )

    redirect = RedirectResponse(url=authorize_url, status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key=SSO_STATE_COOKIE_NAME,
        value=_sign_state(provider, state, nonce, verifier),
        max_age=SSO_STATE_TTL_SECONDS,
        path=SSO_STATE_COOKIE_PATH,
        httponly=True,
        secure=_is_secure(),
        samesite="lax",
    )
    return redirect


@router.get("/{provider}/callback")
async def sso_callback(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Complete an OIDC SSO login: validate, JIT-provision, mint a session.

    Steps: read + verify the signed-state cookie; check the provider matches
    and the ``state`` query param equals the stashed value (CSRF); exchange the
    code with the stashed PKCE verifier; verify the ID-token signature +
    iss/aud/exp + nonce (replay); JIT-provision the user + ``sso_identity``;
    mint the session pair + cookies; 302 to the frontend.
    """
    config = _get_provider(provider)

    # IdP error response (e.g. user denied consent) → bounce to login with a flag.
    if request.query_params.get("error"):
        logger.info("SSO callback IdP error for provider=%s", provider)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="SSO authorization denied"
        )

    code = request.query_params.get("code")
    returned_state = request.query_params.get("state")
    if not code or not returned_state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

    # Recover + verify the stashed login parameters.
    state_cookie = request.cookies.get(SSO_STATE_COOKIE_NAME)
    if not state_cookie:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing SSO state")
    try:
        stash = _decode_state(state_cookie)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid SSO state")

    # The stash must belong to THIS provider (a cookie minted for one provider
    # can't be replayed against another).
    if stash.get("provider") != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="SSO state provider mismatch"
        )

    # CSRF: the state returned by the IdP must match the one we stashed.
    if not secrets.compare_digest(str(stash.get("state", "")), str(returned_state)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SSO state mismatch")

    # redirect_uri allowlist: the callback must be reached at the EXACT URI we
    # registered + sent to the IdP. Defends against open-redirect / mix-up.
    if not _redirect_uri_matches(config.redirect_uri, request):
        logger.warning("SSO redirect_uri mismatch for provider=%s", provider)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="redirect_uri not allowed"
        )

    try:
        discovery = await oidc.discover(config)
        token = await oidc.exchange_code(config, discovery, code=code, code_verifier=stash["cv"])
        claims = await oidc.verify_id_token(
            config,
            discovery,
            id_token=token["id_token"],
            expected_nonce=stash["nonce"],
        )
    except oidc.OIDCError as exc:
        logger.warning("SSO token/id-token verification failed for provider=%s: %s", provider, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="SSO verification failed"
        )

    subject = str(claims["sub"])
    email = claims.get("email")
    role = oidc.map_role(config, claims)

    user = await _jit_provision(db, provider=provider, subject=subject, email=email, role=role)

    # SSO-issued tokens flow through the same minting path as password login,
    # so revocation / refresh-rotation / org scoping all apply unchanged.
    pair = create_token_pair(user.id, user.username, user.role, org_id=user.org_id)

    settings = get_settings()
    redirect = RedirectResponse(url=settings.frontend_url, status_code=status.HTTP_302_FOUND)
    set_auth_cookies(redirect, pair.access_token, pair.refresh_token)
    # One-time state cookie — drop it now that the round-trip is complete.
    redirect.delete_cookie(key=SSO_STATE_COOKIE_NAME, path=SSO_STATE_COOKIE_PATH)
    return redirect


def _redirect_uri_matches(configured: str, request: Request) -> bool:
    """Enforce an exact ``redirect_uri`` allowlist.

    The configured ``redirect_uri`` is the single allowed callback. We compare
    its path against the request path (the host/scheme are governed by the
    deployment's ingress and CORS allowlist). An exact path match is required.
    """
    from urllib.parse import urlsplit

    configured_path = urlsplit(configured).path
    return request.url.path == configured_path


async def _jit_provision(
    db: AsyncSession,
    *,
    provider: str,
    subject: str,
    email: str | None,
    role: str,
) -> UserRow:
    """Find-or-create the user behind an IdP identity (JIT provisioning).

    1. Look up ``sso_identity (provider, subject)`` — a hit returns the linked
       user (the stable path for returning SSO users).
    2. On a miss, find-or-create a ``UserRow``:
       * if ``email`` matches an existing user, link to it (account linking);
       * else create a fresh, password-less user (``password_hash=None``).
       Then insert the ``sso_identity`` row so future logins hit step 1.

    The role from ``role_map`` is applied to NEW users. For an existing local
    user being linked we do NOT silently change their role here (least
    surprise); the IdP-mapped role takes effect for IdP-provisioned accounts.
    """
    existing_identity = await db.execute(
        select(SSOIdentityRow).where(
            SSOIdentityRow.provider == provider,
            SSOIdentityRow.subject == subject,
        )
    )
    identity = existing_identity.scalar_one_or_none()
    if identity is not None:
        user = await db.get(UserRow, identity.user_id)
        if user is not None:
            return user
        # Dangling identity (user deleted) — fall through to recreate.

    user: UserRow | None = None
    if email:
        by_email = await db.execute(select(UserRow).where(UserRow.email == email))
        user = by_email.scalar_one_or_none()

    if user is None:
        # Brand-new JIT user: password-less, role from the IdP mapping.
        username = _derive_username(email, subject)
        user = UserRow(
            id=generate_id("usr"),
            username=username,
            email=email or f"{subject}@{provider}.sso.local",
            password_hash=None,  # SSO-only: no local credential
            role=role,
        )
        db.add(user)
        await db.flush()

    db.add(
        SSOIdentityRow(
            id=generate_id("sso"),
            user_id=user.id,
            provider=provider,
            subject=subject,
            email=email,
        )
    )
    await db.flush()
    return user


def _derive_username(email: str | None, subject: str) -> str:
    """Pick a unique-ish username for a new JIT user.

    Prefer the email local-part; fall back to the subject. A short random
    suffix keeps it collision-resistant against the unique ``username``
    constraint without a retry loop.
    """
    base = (email.split("@", 1)[0] if email else subject) or subject
    base = base[:80]
    return f"{base}-{secrets.token_hex(3)}"
