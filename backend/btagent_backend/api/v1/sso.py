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

from btagent_shared.types.enums import AuditCategory, AuditOutcome
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth import oidc
from btagent_backend.auth.cookies import _is_secure, set_auth_cookies
from btagent_backend.auth.jwt import create_token_pair
from btagent_backend.config import OIDCProviderConfig, get_settings
from btagent_backend.db.models import SSOIdentityRow, UserRow
from btagent_backend.services.audit_trail import AuditTrail

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
    # ``email_verified`` is read ONLY from the cryptographically verified ID
    # token (the dict returned by ``oidc.verify_id_token``), never re-derived
    # from any user-controlled or unverified input. This is the trust anchor
    # that gates account-linking-by-email below.
    email_verified = bool(claims.get("email_verified"))
    role = oidc.map_role(config, claims)

    user = await _jit_provision(
        db,
        provider=provider,
        subject=subject,
        email=email,
        email_verified=email_verified,
        role=role,
    )

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
    email_verified: bool,
    role: str,
) -> UserRow:
    """Find-or-create the user behind an IdP identity (JIT provisioning).

    1. Look up ``sso_identity (provider, subject)`` — a hit returns the linked
       user (the stable path for returning SSO users).
    2. On a miss, find-or-create a ``UserRow``. Account-linking-by-email is
       deliberately constrained to defend against takeover:
       * Email-linking is attempted ONLY when the IdP asserted a **verified**
         email (``email AND email_verified``). An absent/unverified email is
         refused outright (400/409) — never linked, never used to mint a row
         (which would also collide with the unique-email constraint).
       * A verified-email match against an existing user that holds a **local
         password** (``password_hash IS NOT NULL``) is REFUSED with 409: an
         unverified/misconfigured IdP asserting ``email=victim@corp.com`` must
         not silently seize a high-value local-credential account. Linking such
         accounts requires an explicit administrator action.
       * A verified-email match against an **SSO-only** user
         (``password_hash IS NULL``) is auto-linked (the safe linking case).
       * No match + verified email → create a fresh, password-less user.
       Then insert the ``sso_identity`` row so future logins hit step 1.

    The role from ``role_map`` is applied to NEW users. For an existing
    SSO-only user being linked we do NOT silently change their role here (least
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

    # Without a verified email we cannot safely link or create: a brand-new row
    # would either lack a real email or duplicate an existing one (unique
    # constraint). Refuse rather than guess.
    if not (email and email_verified):
        logger.warning(
            "SSO refused: IdP did not assert a verified email for provider=%s subject=%s",
            provider,
            subject,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IdP did not assert a verified email",
        )

    by_email = await db.execute(select(UserRow).where(UserRow.email == email))
    user = by_email.scalar_one_or_none()

    if user is not None:
        # Account-linking gate: never silently bind a local-password account to
        # SSO — that is the takeover vector. Only SSO-only accounts auto-link.
        if user.password_hash is not None:
            logger.warning(
                "SSO refused: verified email %s matches an existing local-password "
                "account for provider=%s; admin linking required",
                email,
                provider,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "An account with this email already exists; "
                    "an administrator must link it to SSO"
                ),
            )
    else:
        # Brand-new JIT user: password-less, role from the IdP mapping.
        username = _derive_username(email, subject)
        user = UserRow(
            id=generate_id("usr"),
            username=username,
            email=email,
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


# ---------------------------------------------------------------------------
# Admin-driven account linking (#169)
# ---------------------------------------------------------------------------
#
# The OIDC callback (``_jit_provision``) deliberately REFUSES (409) to auto-link
# a verified IdP email to an existing **local-password** account — that closes
# an account-takeover vector (a misconfigured IdP asserting a victim's email
# must not silently capture their credentialed account). The cost is that a
# user with a pre-existing password account has no self-serve path to start
# logging in via SSO. These admin endpoints supply the *explicit, authorized,
# audited* override: an operator binds a known ``(provider, subject)`` to a
# chosen ``UserRow``. Because the operator vouches for the mapping, the
# verified-email gate that constrains JIT does not apply here.
#
# Once linked, the next SSO callback hits step 1 of ``_jit_provision`` (lookup
# by ``(provider, subject)``) and returns the linked user directly — bypassing
# the 409. The user's ``password_hash`` is left intact, so they retain local
# login alongside SSO.


class LinkSSOIdentityRequest(BaseModel):
    """Bind an existing user to an IdP ``(provider, subject)`` identity."""

    user_id: str
    provider: str
    subject: str
    email: str | None = None


class SSOIdentityResponse(BaseModel):
    id: str
    user_id: str
    provider: str
    subject: str
    email: str | None
    created_at: datetime

    @classmethod
    def from_row(cls, row: SSOIdentityRow) -> SSOIdentityResponse:
        return cls(
            id=row.id,
            user_id=row.user_id,
            provider=row.provider,
            subject=row.subject,
            email=row.email,
            created_at=row.created_at,
        )


@router.post(
    "/identities",
    response_model=SSOIdentityResponse,
    status_code=status.HTTP_201_CREATED,
)
async def link_sso_identity(
    body: LinkSSOIdentityRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> SSOIdentityResponse:
    """Link an existing account to an IdP identity (admin only, audited).

    Validates that the provider is configured (404), the target user exists
    (404), and the ``(provider, subject)`` pair is not already linked (409).
    The action is recorded on the SHA-256 audit chain.
    """
    user.require_permission("sso:link")

    # Provider must be a configured SSO provider — you can't link to an IdP the
    # platform doesn't know how to authenticate against. Reuses the same 404 as
    # the login/callback routes.
    _get_provider(body.provider)

    target = await db.get(UserRow, body.user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    existing = await db.execute(
        select(SSOIdentityRow).where(
            SSOIdentityRow.provider == body.provider,
            SSOIdentityRow.subject == body.subject,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This IdP identity is already linked to an account",
        )

    identity = SSOIdentityRow(
        id=generate_id("sso"),
        user_id=target.id,
        provider=body.provider,
        subject=body.subject,
        email=body.email,
    )
    db.add(identity)
    await db.flush()

    await AuditTrail(db).record(
        actor=user.username,
        category=AuditCategory.AUTHORIZATION,
        action="sso.identity.link",
        resource=f"user:{target.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "provider": body.provider,
            "subject": body.subject,
            "identity_id": identity.id,
            "target_username": target.username,
        },
    )
    await db.commit()
    logger.info(
        "SSO identity %s linked user=%s provider=%s by admin=%s",
        identity.id,
        target.id,
        body.provider,
        user.username,
    )
    return SSOIdentityResponse.from_row(identity)


@router.get("/identities", response_model=list[SSOIdentityResponse])
async def list_sso_identities(
    user_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[SSOIdentityResponse]:
    """List SSO identities, optionally filtered to one user (admin only).

    Backs the admin UI that shows which IdP identities are bound to an account.
    """
    user.require_permission("sso:link")
    query = select(SSOIdentityRow).order_by(SSOIdentityRow.created_at.desc())
    if user_id is not None:
        query = query.where(SSOIdentityRow.user_id == user_id)
    rows = (await db.execute(query)).scalars().all()
    return [SSOIdentityResponse.from_row(r) for r in rows]


@router.delete("/identities/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink_sso_identity(
    identity_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Unlink an IdP identity (admin only, audited). 404 if it doesn't exist.

    After unlinking, the next SSO login for that ``(provider, subject)`` falls
    back to JIT — which again refuses to silently bind to a password account.
    """
    user.require_permission("sso:unlink")

    identity = await db.get(SSOIdentityRow, identity_id)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SSO identity not found")

    await AuditTrail(db).record(
        actor=user.username,
        category=AuditCategory.AUTHORIZATION,
        action="sso.identity.unlink",
        resource=f"user:{identity.user_id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "provider": identity.provider,
            "subject": identity.subject,
            "identity_id": identity.id,
        },
    )
    await db.delete(identity)
    await db.commit()
    logger.info(
        "SSO identity %s unlinked (user=%s provider=%s) by admin=%s",
        identity_id,
        identity.user_id,
        identity.provider,
        user.username,
    )
