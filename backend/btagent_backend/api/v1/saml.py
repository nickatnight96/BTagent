"""Generic SAML 2.0 SSO endpoints (#170, Phase 2).

The SP-side routes, mirroring the OIDC ``api/v1/sso.py`` structure. Three
endpoints under ``/auth/saml/{provider}``, all UN-authed/public (the user has
no session yet):

* ``GET  /auth/saml/{provider}/login`` — build an ``<AuthnRequest>``, stash its
  id + a RelayState token in a signed httpOnly cookie, then 302 to the IdP.
* ``POST /auth/saml/{provider}/acs`` — the Assertion Consumer Service. Recover
  the signed-state cookie, validate the posted ``SAMLResponse`` (signature,
  conditions, audience, ``InResponseTo`` replay — all in the protocol layer),
  JIT-provision the user against the shared ``sso_identity`` table, then mint a
  normal session and 302 to the frontend.
* ``GET  /auth/saml/{provider}/metadata`` — this SP's metadata XML (operators
  register it with the IdP).

Reuse, not reinvention:
  * ``_jit_provision`` from ``api/v1/sso.py`` is called verbatim with
    ``provider="saml"`` + ``subject=NameID`` — same find-or-create + the same
    no-silent-link-to-password-account gate (409) the OIDC callback uses.
  * Sessions are minted through the SAME ``create_token_pair`` /
    ``set_auth_cookies`` as password + OIDC login, so revocation, refresh
    rotation, and ``org_id`` scoping all apply unchanged.
  * The transient login params live in a signed (JWT, ``type="saml_state"``),
    httpOnly, SameSite=Lax, short-TTL cookie scoped to the SAML callback path —
    its own cookie name + ``type`` so an OIDC state cookie can't be replayed
    here and vice versa.

Packaging: the actual SAML crypto is the optional ``backend[saml]`` extra,
imported lazily in ``auth/saml.py``. If a SAML route is hit on an image without
it, ``SAMLNotInstalledError`` → 503; any other protocol failure → 400 (we never
leak raw XML/crypto errors).
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import get_db
from btagent_backend.api.v1.sso import _jit_provision, _redirect_uri_matches
from btagent_backend.auth import saml as saml_lib
from btagent_backend.auth.cookies import _is_secure, set_auth_cookies
from btagent_backend.auth.jwt import create_token_pair
from btagent_backend.config import SAMLProviderConfig, get_settings

logger = logging.getLogger("btagent.auth.saml.routes")

router = APIRouter(prefix="/auth/saml", tags=["auth", "saml"])

# Signed-state cookie — carries the AuthnRequest id (for InResponseTo) + the
# RelayState token (CSRF on the ACS POST). Own name + path so it can't be
# cross-used with the OIDC state cookie.
SAML_STATE_COOKIE_NAME = "btagent_saml_state"
SAML_STATE_COOKIE_PATH = "/api/v1/auth/saml"
SAML_STATE_TTL_SECONDS = 600


def _get_saml_provider(provider: str) -> SAMLProviderConfig:
    """Resolve a configured SAML provider or 404 (inert when none configured)."""
    config = get_settings().saml_providers.get(provider)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown SAML provider")
    return config


def _sign_saml_state(provider: str, request_id: str, relay_state: str) -> str:
    """Pack the transient login params into a short-TTL signed JWT."""
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "type": "saml_state",
        "provider": provider,
        "rid": request_id,
        "relay": relay_state,
        "exp": now + timedelta(seconds=SAML_STATE_TTL_SECONDS),
        "iat": int(now.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _decode_saml_state(token: str) -> dict:
    """Decode + verify the signed-state JWT. Raises ``JWTError`` on failure."""
    settings = get_settings()
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    if payload.get("type") != "saml_state":
        raise JWTError("not a saml_state token")
    return payload


def _raise_for_saml_error(exc: saml_lib.SAMLError) -> None:
    """Map a protocol-layer error to the right HTTP status (503 vs 400)."""
    if isinstance(exc, saml_lib.SAMLNotInstalledError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAML support is not installed on this server",
        )
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SAML verification failed")


@router.get("/{provider}/login")
async def saml_login(provider: str) -> RedirectResponse:
    """Begin a SAML SSO login: 302 to the IdP with a stashed state cookie."""
    config = _get_saml_provider(provider)
    relay_state = secrets.token_urlsafe(24)

    try:
        idp_metadata = await saml_lib.fetch_metadata(provider, config)
        request_id, location = saml_lib.build_authn_request(
            config, idp_metadata, relay_state=relay_state
        )
    except saml_lib.SAMLError as exc:
        logger.warning("SAML login failed for provider=%s: %s", provider, exc)
        _raise_for_saml_error(exc)

    redirect = RedirectResponse(url=location, status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key=SAML_STATE_COOKIE_NAME,
        value=_sign_saml_state(provider, request_id, relay_state),
        max_age=SAML_STATE_TTL_SECONDS,
        path=SAML_STATE_COOKIE_PATH,
        httponly=True,
        secure=_is_secure(),
        samesite="lax",
    )
    return redirect


@router.post("/{provider}/acs")
async def saml_acs(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Assertion Consumer Service: validate the assertion, JIT-provision, mint a session."""
    config = _get_saml_provider(provider)

    form = await request.form()
    saml_response = form.get("SAMLResponse")
    returned_relay = form.get("RelayState")
    if not saml_response:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing SAMLResponse")

    # Recover + verify the stashed login parameters.
    state_cookie = request.cookies.get(SAML_STATE_COOKIE_NAME)
    if not state_cookie:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing SAML state")
    try:
        stash = _decode_saml_state(state_cookie)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid SAML state")

    # The stash must belong to THIS provider.
    if stash.get("provider") != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="SAML state provider mismatch"
        )
    # CSRF: the RelayState the IdP echoed must match what we stashed.
    if not secrets.compare_digest(str(stash.get("relay", "")), str(returned_relay or "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="SAML RelayState mismatch"
        )
    # ACS must be reached at the exact URI we registered (open-redirect / mix-up defense).
    if not _redirect_uri_matches(config.acs_url, request):
        logger.warning("SAML ACS path mismatch for provider=%s", provider)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="acs_url not allowed")

    try:
        idp_metadata = await saml_lib.fetch_metadata(provider, config)
        assertion = saml_lib.parse_response(
            config,
            idp_metadata,
            saml_response=str(saml_response),
            # InResponseTo (replay): the assertion must answer the request we issued.
            outstanding={stash["rid"]: config.acs_url},
        )
    except saml_lib.SAMLError as exc:
        logger.warning("SAML ACS validation failed for provider=%s: %s", provider, exc)
        _raise_for_saml_error(exc)

    email = saml_lib.extract_email(assertion, config)
    if not email:
        # Mirrors the OIDC unverified-email gate: without an email we can't
        # safely link or create. A signed assertion makes the email verified.
        logger.warning("SAML refused: assertion carried no email for provider=%s", provider)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="SAML assertion carried no email"
        )
    role = saml_lib.map_role(config, saml_lib.extract_roles(assertion, config))

    user = await _jit_provision(
        db,
        provider="saml",
        subject=assertion.name_id,
        email=email,
        # A validly-signed assertion is the IdP's non-repudiation guarantee, so
        # the email counts as verified. The no-silent-link-to-password-account
        # gate inside _jit_provision (409) still applies.
        email_verified=True,
        role=role,
    )

    pair = create_token_pair(user.id, user.username, user.role, org_id=user.org_id)
    settings = get_settings()
    redirect = RedirectResponse(url=settings.frontend_url, status_code=status.HTTP_302_FOUND)
    set_auth_cookies(redirect, pair.access_token, pair.refresh_token)
    redirect.delete_cookie(key=SAML_STATE_COOKIE_NAME, path=SAML_STATE_COOKIE_PATH)
    return redirect


@router.get("/{provider}/metadata")
async def saml_metadata(provider: str) -> Response:
    """Return this SP's SAML metadata XML for the given provider."""
    config = _get_saml_provider(provider)
    try:
        xml = saml_lib.generate_sp_metadata(config)
    except saml_lib.SAMLError as exc:
        logger.warning("SAML metadata generation failed for provider=%s: %s", provider, exc)
        _raise_for_saml_error(exc)
    return Response(content=xml, media_type="application/samlmetadata+xml")
