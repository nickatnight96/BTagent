"""Generic OIDC (OpenID Connect) client for SSO (#144, Phase 1b).

The *crypto + protocol* layer for authorization-code + PKCE SSO. It has no
FastAPI/DB concerns — those live in ``api/v1/sso.py``. Everything here is
small, mockable async functions over ``httpx`` so the test suite can fake the
IdP (discovery / token / JWKS) with an ``httpx.MockTransport`` — NO live
network.

Flow implemented:

1. ``discover()`` — fetch ``{issuer}/.well-known/openid-configuration`` to learn
   the authorize / token / JWKS endpoints (cached per-issuer).
2. ``build_authorize_url()`` — construct the authorize URL with ``state`` +
   ``nonce`` + PKCE ``code_challenge`` (S256).
3. ``exchange_code()`` — POST the code (with the PKCE ``code_verifier``) to the
   token endpoint and return the raw token response.
4. ``verify_id_token()`` — fetch the JWKS, verify the ID-token *signature*, then
   validate ``iss`` / ``aud`` / ``exp`` and the ``nonce`` we issued.
5. ``map_role()`` — map the configured ``role_claim`` value(s) → a BTagent role
   via ``role_map`` (default ``analyst``).

Security notes:
  * The ID token signature is verified against the IdP JWKS — we never trust an
    unsigned/unverified token.
  * ``state`` (CSRF) and ``nonce`` (replay) are generated here and validated by
    the route layer against values stashed server-side at /login time.
  * PKCE (S256) is always sent so an intercepted code is useless without the
    verifier.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError
from btagent_shared.utils.secrets import resolve_secret

from btagent_backend.config import OIDCProviderConfig

logger = logging.getLogger("btagent.auth.oidc")

# Discovery / JWKS HTTP timeout (seconds). Kept short so a misbehaving IdP can't
# hang the request worker.
_HTTP_TIMEOUT = 10.0

# Signature algorithms we accept for ID tokens. RS256 is the OIDC default;
# ES256 covers EC-keyed IdPs. We deliberately do NOT allow ``none`` or HS*
# (symmetric) — an attacker who learned the client_secret could otherwise forge
# an HS256 ID token.
_ALLOWED_ID_TOKEN_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")

# Test seam: when set (by the test suite), every ``httpx.AsyncClient`` opened
# here uses this transport (an ``httpx.MockTransport`` faking the IdP), so all
# OIDC tests run with NO live network. ``None`` in prod/dev → real network.
_http_transport: httpx.AsyncBaseTransport | None = None


def _async_client() -> httpx.AsyncClient:
    """Build the httpx client, honouring the test transport seam."""
    if _http_transport is not None:
        return httpx.AsyncClient(timeout=_HTTP_TIMEOUT, transport=_http_transport)
    return httpx.AsyncClient(timeout=_HTTP_TIMEOUT)


class OIDCError(RuntimeError):
    """Raised on any OIDC protocol failure (discovery, token, signature, claims).

    The route layer maps this to a 400 so we never leak raw IdP/crypto errors
    to the browser.
    """


@dataclass
class OIDCDiscovery:
    """Subset of the IdP discovery document we use."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


# Per-issuer discovery cache (process-local). Discovery docs are stable; caching
# avoids a network round-trip on every login. ``_reset_for_tests`` clears it.
_discovery_cache: dict[str, OIDCDiscovery] = {}
# Per-jwks-uri JWKS cache (parsed KeySet).
_jwks_cache: dict[str, object] = {}


def _reset_for_tests() -> None:
    """Clear the discovery/JWKS caches (used by the test suite)."""
    _discovery_cache.clear()
    _jwks_cache.clear()


# ---------------------------------------------------------------------------
# PKCE + state/nonce primitives
# ---------------------------------------------------------------------------


def generate_state() -> str:
    """Return a fresh, unguessable CSRF state token."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Return a fresh, unguessable nonce (binds the ID token to this request)."""
    return secrets.token_urlsafe(32)


def generate_pkce_verifier() -> str:
    """Return a high-entropy PKCE ``code_verifier`` (RFC 7636 §4.1).

    43–128 chars of unreserved [A-Z a-z 0-9 -._~]; ``token_urlsafe(64)`` yields
    ~86 url-safe chars, comfortably inside the range.
    """
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier: str) -> str:
    """Compute the S256 ``code_challenge`` for a ``code_verifier`` (RFC 7636)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def discover(provider: OIDCProviderConfig) -> OIDCDiscovery:
    """Fetch + cache the IdP discovery document for ``provider.issuer``."""
    issuer = provider.issuer.rstrip("/")
    cached = _discovery_cache.get(issuer)
    if cached is not None:
        return cached

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with _async_client() as client:
            resp = await client.get(url)
            resp.raise_for_status()
            doc = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCError(f"OIDC discovery failed for issuer {issuer!r}: {exc}") from exc

    try:
        discovery = OIDCDiscovery(
            issuer=doc["issuer"],
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            jwks_uri=doc["jwks_uri"],
        )
    except KeyError as exc:
        raise OIDCError(f"OIDC discovery document missing required field: {exc}") from exc

    _discovery_cache[issuer] = discovery
    return discovery


# ---------------------------------------------------------------------------
# Authorize URL
# ---------------------------------------------------------------------------


def build_authorize_url(
    provider: OIDCProviderConfig,
    discovery: OIDCDiscovery,
    *,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """Build the IdP authorize URL (authorization-code + PKCE S256)."""
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": provider.redirect_uri,
        "scope": " ".join(provider.scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in discovery.authorization_endpoint else "?"
    return f"{discovery.authorization_endpoint}{sep}{urlencode(params)}"


# ---------------------------------------------------------------------------
# Code exchange
# ---------------------------------------------------------------------------


async def exchange_code(
    provider: OIDCProviderConfig,
    discovery: OIDCDiscovery,
    *,
    code: str,
    code_verifier: str,
) -> dict:
    """Exchange an authorization ``code`` (+ PKCE verifier) for tokens.

    Returns the raw token response (expects an ``id_token``). The client secret
    is resolved lazily here via ``resolve_secret`` so an unresolved
    ``${secret:...}`` reference surfaces as an OIDC error at request time rather
    than breaking app boot.
    """
    client_secret = resolve_secret(provider.client_secret) if provider.client_secret else ""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": provider.redirect_uri,
        "client_id": provider.client_id,
        "code_verifier": code_verifier,
    }
    # Send the secret for confidential clients (most IdPs); harmless for public
    # clients that ignore it.
    if client_secret:
        data["client_secret"] = client_secret

    try:
        async with _async_client() as client:
            resp = await client.post(
                discovery.token_endpoint,
                data=data,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            token = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCError(f"OIDC token exchange failed: {exc}") from exc

    if "id_token" not in token:
        raise OIDCError("OIDC token response did not include an id_token")
    return token


# ---------------------------------------------------------------------------
# JWKS + ID-token verification
# ---------------------------------------------------------------------------


async def _fetch_jwks(jwks_uri: str):
    """Fetch + cache the IdP JWKS as an authlib KeySet."""
    cached = _jwks_cache.get(jwks_uri)
    if cached is not None:
        return cached
    try:
        async with _async_client() as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCError(f"OIDC JWKS fetch failed: {exc}") from exc
    key_set = JsonWebKey.import_key_set(jwks)
    _jwks_cache[jwks_uri] = key_set
    return key_set


async def verify_id_token(
    provider: OIDCProviderConfig,
    discovery: OIDCDiscovery,
    *,
    id_token: str,
    expected_nonce: str,
) -> dict:
    """Verify the ID token *signature* against the JWKS, then validate claims.

    Validates, in order:
      1. signature — against the IdP JWKS (RS*/ES* only; never ``none``/HS*);
      2. ``iss`` — must equal the discovered issuer;
      3. ``aud`` — must contain our ``client_id``;
      4. ``exp`` — not expired (authlib's claims validation);
      5. ``nonce`` — must equal the nonce we generated for this login.

    Returns the validated claims dict on success; raises ``OIDCError`` otherwise.
    """
    key_set = await _fetch_jwks(discovery.jwks_uri)

    jwt = JsonWebToken(list(_ALLOWED_ID_TOKEN_ALGS))
    claims_options = {
        "iss": {"essential": True, "value": discovery.issuer},
        "aud": {"essential": True, "value": provider.client_id},
        "exp": {"essential": True},
    }
    try:
        claims = jwt.decode(id_token, key_set, claims_options=claims_options)
        # Validates exp/iss/aud per claims_options (and exp leeway=0).
        claims.validate()
    except JoseError as exc:
        raise OIDCError(f"OIDC ID-token verification failed: {exc}") from exc
    except Exception as exc:  # defensive: malformed token → uniform error
        raise OIDCError(f"OIDC ID-token verification failed: {exc}") from exc

    # Nonce binds the ID token to the specific login request (replay defense).
    # authlib does not check nonce automatically, so we enforce it explicitly.
    token_nonce = claims.get("nonce")
    if not token_nonce or not secrets.compare_digest(str(token_nonce), str(expected_nonce)):
        raise OIDCError("OIDC ID-token nonce mismatch")

    if not claims.get("sub"):
        raise OIDCError("OIDC ID-token missing required 'sub' claim")

    return dict(claims)


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


def map_role(provider: OIDCProviderConfig, claims: dict) -> str:
    """Map the configured ``role_claim`` value(s) → a BTagent role.

    The claim may be a string or a list of strings (e.g. ``groups``). The
    actual resolution + ``UserRole`` validation lives in the shared
    ``_role_map.resolve_role`` helper (also used by the SAML layer) so both SSO
    protocols share identical, security-sensitive semantics.
    """
    from btagent_backend.auth._role_map import resolve_role

    raw = claims.get(provider.role_claim)
    if raw is None:
        values: list[str] = []
    elif isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, (list, tuple)):
        values = [str(v) for v in raw]
    else:
        values = [str(raw)]

    return resolve_role(
        role_map=provider.role_map,
        default_role=provider.default_role,
        candidate_values=values,
    )
