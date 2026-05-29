"""Generic SAML 2.0 SSO protocol layer (#170, Phase 2).

The *crypto + protocol* half of SAML SSO — the SP-side mirror of ``auth/oidc.py``.
It has no FastAPI/DB concerns (those live in ``api/v1/saml.py``); everything here
is small functions over ``pysaml2`` + ``httpx`` so the test suite can drive a
fake IdP with NO live network.

Flow implemented (SP-initiated, HTTP-POST ACS):

1. ``fetch_metadata()`` — obtain the IdP metadata XML: fetched + cached from
   ``idp_metadata_url`` (preferred), or built inline from the manual
   ``idp_entity_id`` / ``sso_url`` / ``x509cert`` fields.
2. ``build_authn_request()`` — construct the ``<AuthnRequest>`` and return its
   id + the IdP redirect URL. The id is stashed (by the route layer) so the
   ACS can enforce ``InResponseTo`` (replay defense).
3. ``parse_response()`` — feed the base64 ``SAMLResponse`` to pysaml2, which
   verifies the **assertion signature**, ``Conditions`` (NotBefore /
   NotOnOrAfter), ``AudienceRestriction``, and ``InResponseTo`` (via the
   ``outstanding`` map). Returns a normalised ``SAMLAssertion``.
4. ``extract_email`` / ``extract_roles`` / ``map_role`` — pull the subject's
   email + role attribute values and map them to a BTagent role (shared
   ``_role_map.resolve_role`` with OIDC).

Security posture:
  * The SP requires **signed assertions** (``want_assertions_signed``) and
    forbids unsolicited responses (``allow_unsolicited=False``) so every
    accepted assertion answers an ``AuthnRequest`` we issued.
  * A SAML assertion has no ``email_verified`` claim — a validly *signed*
    assertion carrying an email is treated as verified (the signature is the
    IdP's non-repudiation guarantee). The no-silent-link-to-password-account
    gate in ``_jit_provision`` still applies downstream.

Packaging: ``pysaml2`` (and the ``xmlsec1`` binary it shells out to) is an
OPTIONAL ``backend[saml]`` extra. It is imported lazily via ``_load_saml`` so
importing this module — and booting the app — costs nothing on the slim image;
a SAML route hit on an image without the extra raises ``SAMLNotInstalledError``
(→ 503 at the route layer).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx
from btagent_shared.utils.secrets import resolve_secret

from btagent_backend.auth._role_map import resolve_role
from btagent_backend.config import SAMLProviderConfig

logger = logging.getLogger("btagent.auth.saml")

# Metadata fetch HTTP timeout (seconds) — kept short so a misbehaving IdP can't
# hang the request worker.
_HTTP_TIMEOUT = 10.0

# Test seam: when set (by the test suite), the metadata fetch uses this
# transport (an ``httpx.MockTransport`` faking the IdP) so tests run with NO
# live network. ``None`` in prod/dev → real network.
_http_transport: httpx.AsyncBaseTransport | None = None

# Lazily-bound pysaml2 names (populated by ``_load_saml``).
_saml: dict[str, object] = {}
_saml_loaded = False


class SAMLError(RuntimeError):
    """Raised on any SAML protocol failure (metadata, parse, signature, claims).

    The route layer maps this to a 400 so we never leak raw XML/crypto errors
    to the browser.
    """


class SAMLNotInstalledError(SAMLError):
    """Raised when a SAML route is used but the ``backend[saml]`` extra is absent.

    The route layer maps this to a 503 — the feature is configured but the image
    it's running on did not ship the optional pysaml2 + xmlsec dependencies.
    """


def _load_saml() -> None:
    """Import pysaml2 on first use; bind the names this module needs.

    Raises ``SAMLNotInstalledError`` if the ``backend[saml]`` extra (and its
    ``xmlsec1`` system binary) is not installed — so ``import …auth.saml`` and
    app boot never require it.
    """
    global _saml_loaded
    if _saml_loaded:
        return
    try:
        from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
        from saml2.client import Saml2Client
        from saml2.config import SPConfig
        from saml2.metadata import entity_descriptor
        from saml2.sigver import get_xmlsec_binary
    except ImportError as exc:  # pragma: no cover - exercised via the 503 path
        raise SAMLNotInstalledError(
            "SAML support requires the optional dependencies: "
            "pip install 'btagent-backend[saml]' (and the xmlsec1 system binary)"
        ) from exc

    _saml.update(
        BINDING_HTTP_POST=BINDING_HTTP_POST,
        BINDING_HTTP_REDIRECT=BINDING_HTTP_REDIRECT,
        Saml2Client=Saml2Client,
        SPConfig=SPConfig,
        entity_descriptor=entity_descriptor,
        get_xmlsec_binary=get_xmlsec_binary,
    )
    _saml_loaded = True


def _reset_for_tests() -> None:
    """Clear the metadata cache (used by the test suite)."""
    _metadata_cache.clear()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

# Per-provider IdP metadata cache: {provider_key: (xml, expires_at_monotonic)}.
_metadata_cache: dict[str, tuple[str, float]] = {}


def _async_client() -> httpx.AsyncClient:
    """Build the httpx client, honouring the test transport seam."""
    if _http_transport is not None:
        return httpx.AsyncClient(timeout=_HTTP_TIMEOUT, transport=_http_transport)
    return httpx.AsyncClient(timeout=_HTTP_TIMEOUT)


def _clean_cert(cert: str) -> str:
    """Strip PEM armor + whitespace, leaving the bare base64 DER body."""
    lines = [
        ln.strip() for ln in cert.strip().splitlines() if ln.strip() and not ln.startswith("-----")
    ]
    return "".join(lines)


def _build_idp_metadata_xml(entity_id: str, sso_url: str, x509cert: str) -> str:
    """Build a minimal IdP ``EntityDescriptor`` from manual config fields.

    Used when an operator supplies ``idp_entity_id`` + ``sso_url`` + ``x509cert``
    instead of an ``idp_metadata_url``. The cert is the IdP's signing key.
    """
    cert_body = _clean_cert(x509cert)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}">'
        "<IDPSSODescriptor protocolSupportEnumeration="
        '"urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><KeyInfo '
        'xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>'
        f"<X509Certificate>{cert_body}</X509Certificate>"
        "</X509Data></KeyInfo></KeyDescriptor>"
        "<SingleSignOnService "
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{sso_url}"/>'
        "<SingleSignOnService "
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{sso_url}"/>'
        "</IDPSSODescriptor></EntityDescriptor>"
    )


async def fetch_metadata(provider_key: str, cfg: SAMLProviderConfig) -> str:
    """Return the IdP metadata XML for ``cfg`` (cached per provider).

    Manual config (no ``idp_metadata_url``) builds the metadata inline from the
    entity id / SSO URL / signing cert; the cert is resolved here (lazily, via
    ``resolve_secret``) so an unresolved ``${secret:...}`` reference surfaces as
    a SAML error at request time rather than breaking app boot.
    """
    if not cfg.idp_metadata_url:
        cert = resolve_secret(cfg.x509cert) if cfg.x509cert else ""
        if not cert:
            raise SAMLError("SAML provider has no idp_metadata_url and no x509cert")
        return _build_idp_metadata_xml(cfg.idp_entity_id or "", cfg.sso_url or "", cert)

    cached = _metadata_cache.get(provider_key)
    now = time.monotonic()
    if cached is not None and cached[1] > now:
        return cached[0]

    try:
        async with _async_client() as client:
            resp = await client.get(cfg.idp_metadata_url)
            resp.raise_for_status()
            xml = resp.text
    except httpx.HTTPError as exc:
        raise SAMLError(f"SAML metadata fetch failed for {provider_key!r}: {exc}") from exc

    _metadata_cache[provider_key] = (xml, now + cfg.metadata_ttl_seconds)
    return xml


# ---------------------------------------------------------------------------
# SP client + AuthnRequest
# ---------------------------------------------------------------------------


def _sp_config_dict(cfg: SAMLProviderConfig, idp_metadata_xml: str | None) -> dict:
    """Build the pysaml2 SPConfig dict for ``cfg``.

    ``idp_metadata_xml`` is required for the login/ACS flows (the SP needs the
    IdP cert to validate signatures); it is ``None`` only for SP-metadata
    *generation*, which describes ourselves and needs no IdP.
    """
    BINDING_HTTP_POST = _saml["BINDING_HTTP_POST"]
    get_xmlsec_binary = _saml["get_xmlsec_binary"]
    conf: dict = {
        "entityid": cfg.sp_entity_id,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(cfg.acs_url, BINDING_HTTP_POST)],
                },
                # Require signed assertions and forbid unsolicited (IdP-initiated)
                # responses — every accepted assertion must answer an
                # AuthnRequest we issued (InResponseTo / replay defense).
                "allow_unsolicited": False,
                "want_assertions_signed": True,
                "want_response_signed": False,
                "authn_requests_signed": False,
                "name_id_format": cfg.name_id_format,
            },
        },
        "xmlsec_binary": get_xmlsec_binary(),
        # IdPs vary wildly in which attributes they emit; don't reject unknowns.
        "allow_unknown_attributes": True,
    }
    if idp_metadata_xml is not None:
        conf["metadata"] = {"inline": [idp_metadata_xml]}
    return conf


def generate_sp_metadata(cfg: SAMLProviderConfig) -> str:
    """Return this SP's ``EntityDescriptor`` XML (served at ``/metadata``).

    Operators register this with the IdP. It describes our ACS endpoint +
    AssertionsSigned posture and needs no IdP metadata.
    """
    _load_saml()
    SPConfig = _saml["SPConfig"]
    entity_descriptor = _saml["entity_descriptor"]
    conf = SPConfig()
    conf.load(_sp_config_dict(cfg, None))
    return entity_descriptor(conf).to_string().decode()


def _build_client(cfg: SAMLProviderConfig, idp_metadata_xml: str):
    """Construct a pysaml2 ``Saml2Client`` for ``cfg``."""
    _load_saml()
    SPConfig = _saml["SPConfig"]
    Saml2Client = _saml["Saml2Client"]
    conf = SPConfig()
    conf.load(_sp_config_dict(cfg, idp_metadata_xml))
    return Saml2Client(config=conf)


def build_authn_request(
    cfg: SAMLProviderConfig, idp_metadata_xml: str, *, relay_state: str = ""
) -> tuple[str, str]:
    """Build an ``<AuthnRequest>``; return ``(request_id, idp_redirect_url)``.

    The ``request_id`` MUST be stashed server-side and matched against the
    assertion's ``InResponseTo`` at the ACS (replay defense).
    """
    _load_saml()
    client = _build_client(cfg, idp_metadata_xml)
    BINDING_HTTP_REDIRECT = _saml["BINDING_HTTP_REDIRECT"]
    try:
        request_id, info = client.prepare_for_authenticate(
            relay_state=relay_state, binding=BINDING_HTTP_REDIRECT
        )
    except Exception as exc:  # pysaml2 raises a variety of types
        raise SAMLError(f"failed to build SAML AuthnRequest: {exc}") from exc

    location = dict(info.get("headers", [])).get("Location")
    if not location:
        raise SAMLError("SAML AuthnRequest produced no redirect Location")
    return request_id, location


# ---------------------------------------------------------------------------
# Response parsing + validation
# ---------------------------------------------------------------------------


@dataclass
class SAMLAssertion:
    """Normalised, validated SAML assertion (signature + conditions checked)."""

    name_id: str
    attributes: dict[str, list[str]]
    in_response_to: str | None


def parse_response(
    cfg: SAMLProviderConfig,
    idp_metadata_xml: str,
    *,
    saml_response: str,
    outstanding: dict[str, str],
) -> SAMLAssertion:
    """Parse + validate a base64 ``SAMLResponse`` (HTTP-POST binding).

    pysaml2 verifies, inside ``parse_authn_request_response``:
      * the **assertion signature** against the IdP cert (``want_assertions_signed``);
      * ``Conditions`` NotBefore / NotOnOrAfter (with skew);
      * ``AudienceRestriction`` == our ``sp_entity_id``;
      * ``InResponseTo`` is one of the ``outstanding`` request ids we issued.

    ``outstanding`` maps ``{request_id: came_from_url}`` for the AuthnRequest(s)
    this session has open. Any failure raises ``SAMLError``.
    """
    _load_saml()
    client = _build_client(cfg, idp_metadata_xml)
    BINDING_HTTP_POST = _saml["BINDING_HTTP_POST"]
    try:
        authn_response = client.parse_authn_request_response(
            saml_response, BINDING_HTTP_POST, outstanding=outstanding
        )
    except Exception as exc:
        # Uniform error — signature/condition/audience/replay all collapse here.
        raise SAMLError(f"SAML response validation failed: {exc}") from exc

    if authn_response is None:
        raise SAMLError("SAML response could not be parsed")

    subject = authn_response.get_subject()
    name_id = getattr(subject, "text", None)
    if not name_id:
        raise SAMLError("SAML assertion has no subject NameID")

    # get_identity() returns {attr_name: [values]} already friendly-mapped.
    identity = authn_response.get_identity() or {}
    attributes: dict[str, list[str]] = {
        k: [str(v) for v in (vals if isinstance(vals, list) else [vals])]
        for k, vals in identity.items()
    }

    return SAMLAssertion(
        name_id=str(name_id),
        attributes=attributes,
        in_response_to=getattr(authn_response, "in_response_to", None),
    )


# ---------------------------------------------------------------------------
# Email + role extraction
# ---------------------------------------------------------------------------


def extract_email(assertion: SAMLAssertion, cfg: SAMLProviderConfig) -> str | None:
    """Resolve the user's email from the configured attribute, else the NameID.

    When ``email_attr`` is set, the first value of that attribute is used. When
    it is unset, the NameID is used IFF it looks like an email address (the
    default ``emailAddress`` NameID format). Returns ``None`` if neither yields
    a plausible address — the route layer then refuses (same gate as OIDC).
    """
    if cfg.email_attr:
        values = assertion.attributes.get(cfg.email_attr) or []
        return values[0] if values else None
    # Fall back to NameID when it's email-shaped.
    return assertion.name_id if "@" in assertion.name_id else None


def extract_roles(assertion: SAMLAssertion, cfg: SAMLProviderConfig) -> list[str]:
    """Return the (possibly multi-valued) role attribute values, or ``[]``."""
    return list(assertion.attributes.get(cfg.role_attr, []))


def map_role(cfg: SAMLProviderConfig, role_values: list[str]) -> str:
    """Map IdP role attribute values → a BTagent role (shared with OIDC)."""
    return resolve_role(
        role_map=cfg.role_map,
        default_role=cfg.default_role,
        candidate_values=role_values,
    )
