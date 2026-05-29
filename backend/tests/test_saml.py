"""Tests for the SAML 2.0 SSO protocol layer (#170, Phase 2).

Two layers:

* **Layer A — runs everywhere (no xmlsec needed).** Config validation, role
  mapping (shared with OIDC), email/role attribute extraction, and the
  lazy-import 503 seam. These import ``btagent_backend.auth.saml`` but never
  trigger the pysaml2 import (it is lazy), so they run in the default
  ``backend-tests`` CI job which does NOT install ``backend[saml]``.

* **Layer B — gated on the ``backend[saml]`` extra (``requires_pysaml2``).**
  Full crypto: a real pysaml2 IdP mints signed ``<Response>`` assertions which
  the SP layer validates. Covers happy path + the security-critical negatives
  (unsigned, tampered signature, replayed/unknown ``InResponseTo``, wrong
  audience, expired ``NotOnOrAfter``). These run only where pysaml2 + the
  ``xmlsec1`` binary are installed (the dedicated ``saml-tests`` CI job, and
  any dev box with the extra). In default CI ``import saml2`` fails →
  ``PYSAML2_AVAILABLE`` is False → the whole layer skips, staying green.
"""

from __future__ import annotations

import base64
import os
import tempfile
from datetime import UTC, datetime, timedelta

import pytest

from btagent_backend.auth import saml as S
from btagent_backend.config import SAMLProviderConfig

try:  # the extra (and the xmlsec1 binary) install together
    import saml2  # noqa: F401

    PYSAML2_AVAILABLE = True
except Exception:
    PYSAML2_AVAILABLE = False

requires_pysaml2 = pytest.mark.skipif(
    not PYSAML2_AVAILABLE, reason="backend[saml] extra (pysaml2 + xmlsec1) not installed"
)

IDP_ENTITY = "https://idp.test/metadata"
SSO_URL = "https://idp.test/sso"
SP_ENTITY = "https://sp.test"
ACS = "https://sp.test/api/v1/auth/saml/test/acs"


def _cfg(**over) -> SAMLProviderConfig:
    base = dict(
        idp_entity_id=IDP_ENTITY,
        sso_url=SSO_URL,
        x509cert="dummy-pem",  # overridden with a real cert in layer B
        sp_entity_id=SP_ENTITY,
        acs_url=ACS,
        role_attr="Role",
        role_map={"soc-admins": "admin", "soc-seniors": "senior_analyst"},
        default_role="analyst",
    )
    base.update(over)
    return SAMLProviderConfig(**base)


# ===========================================================================
# Layer A — no pysaml2 required
# ===========================================================================


def test_extract_email_prefers_attribute_then_nameid():
    cfg = _cfg(email_attr="mail")
    a = S.SAMLAssertion(
        name_id="nid-123", attributes={"mail": ["alice@corp.test"]}, in_response_to="x"
    )
    assert S.extract_email(a, cfg) == "alice@corp.test"

    # No email_attr → fall back to NameID iff it looks like an email.
    cfg2 = _cfg(email_attr=None)
    a_email_nid = S.SAMLAssertion(name_id="bob@corp.test", attributes={}, in_response_to="x")
    assert S.extract_email(a_email_nid, cfg2) == "bob@corp.test"
    a_opaque_nid = S.SAMLAssertion(name_id="opaque-subject", attributes={}, in_response_to="x")
    assert S.extract_email(a_opaque_nid, cfg2) is None


def test_extract_roles_and_map_role():
    cfg = _cfg()
    a = S.SAMLAssertion(
        name_id="x", attributes={"Role": ["soc-seniors", "soc-admins"]}, in_response_to="x"
    )
    assert S.extract_roles(a, cfg) == ["soc-seniors", "soc-admins"]
    # First mapped value wins.
    assert S.map_role(cfg, S.extract_roles(a, cfg)) == "senior_analyst"
    # Unmapped / empty → default.
    assert S.map_role(cfg, ["unknown-group"]) == "analyst"
    assert S.map_role(cfg, []) == "analyst"


def test_unmapped_or_invalid_role_falls_back_to_default():
    # A role_map pointing at a bogus BTagent role must NOT grant it.
    cfg = _cfg(role_map={"g": "superuser"}, default_role="analyst")
    assert S.map_role(cfg, ["g"]) == "analyst"


def test_config_requires_idp_metadata_or_manual_fields():
    with pytest.raises(Exception):
        SAMLProviderConfig(sp_entity_id=SP_ENTITY, acs_url=ACS)  # neither path supplied
    # metadata-url path is valid on its own
    SAMLProviderConfig(idp_metadata_url="https://idp/meta", sp_entity_id=SP_ENTITY, acs_url=ACS)


def test_missing_extra_surfaces_not_installed_error(monkeypatch):
    """If pysaml2 is absent, protocol calls raise SAMLNotInstalledError (→ 503)."""

    def boom() -> None:
        raise S.SAMLNotInstalledError("no extra")

    monkeypatch.setattr(S, "_load_saml", boom)
    assert issubclass(S.SAMLNotInstalledError, S.SAMLError)
    with pytest.raises(S.SAMLNotInstalledError):
        S.build_authn_request(_cfg(), "<EntityDescriptor/>")


async def test_fetch_metadata_manual_builds_inline_xml():
    """Manual-config providers build IdP metadata inline (no network)."""
    cfg = _cfg(x509cert="-----BEGIN CERTIFICATE-----\nAAAB\n-----END CERTIFICATE-----")
    xml = await S.fetch_metadata("test", cfg)
    assert IDP_ENTITY in xml and SSO_URL in xml
    assert "<X509Certificate>AAAB</X509Certificate>" in xml  # armor stripped


# ===========================================================================
# Layer B — requires the backend[saml] extra (pysaml2 + xmlsec1)
# ===========================================================================


class _TestIdP:
    """A real pysaml2 IdP that mints signed SAML responses for the SP layer."""

    def __init__(self, lifetime_minutes: int = 15):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
        from saml2.config import IdPConfig
        from saml2.metadata import entity_descriptor
        from saml2.server import Server
        from saml2.sigver import get_xmlsec_binary

        self._work = tempfile.mkdtemp()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        key_file = os.path.join(self._work, "idp.key")
        cert_file = os.path.join(self._work, "idp.crt")
        with open(key_file, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self.cert_pem = open(cert_file).read()

        sp_md = os.path.join(self._work, "sp.xml")
        with open(sp_md, "w") as f:
            f.write(
                f'<?xml version="1.0"?>'
                f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
                f'entityID="{SP_ENTITY}"><SPSSODescriptor '
                f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
                f'AuthnRequestsSigned="false" WantAssertionsSigned="true">'
                f"<AssertionConsumerService "
                f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
                f'Location="{ACS}" index="0" isDefault="true"/>'
                f"</SPSSODescriptor></EntityDescriptor>"
            )

        conf = IdPConfig()
        conf.load(
            {
                "entityid": IDP_ENTITY,
                "service": {
                    "idp": {
                        "endpoints": {
                            "single_sign_on_service": [
                                (SSO_URL, BINDING_HTTP_REDIRECT),
                                (SSO_URL, BINDING_HTTP_POST),
                            ],
                        },
                        "policy": {"default": {"lifetime": {"minutes": lifetime_minutes}}},
                    },
                },
                "key_file": key_file,
                "cert_file": cert_file,
                "metadata": {"local": [sp_md]},
                "xmlsec_binary": get_xmlsec_binary(),
            }
        )
        self.metadata_xml = entity_descriptor(conf).to_string().decode()
        self._server = Server(config=conf)

    def make_response(
        self,
        in_response_to: str,
        *,
        email: str = "alice@corp.test",
        roles=("soc-admins",),
        audience: str = SP_ENTITY,
        sign: bool = True,
    ) -> str:
        from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NameID

        resp = self._server.create_authn_response(
            identity={"Role": list(roles), "mail": [email]},
            in_response_to=in_response_to,
            destination=ACS,
            sp_entity_id=audience,
            name_id=NameID(format=NAMEID_FORMAT_EMAILADDRESS, text=email),
            authn={
                "class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                "authn_auth": IDP_ENTITY,
            },
            sign_assertion=sign,
        )
        return base64.b64encode(str(resp).encode()).decode()


@pytest.fixture(scope="module")
def idp():
    return _TestIdP()


def _cfg_with_cert(idp: _TestIdP, **over) -> SAMLProviderConfig:
    return _cfg(x509cert=idp.cert_pem, **over)


@requires_pysaml2
def test_build_authn_request_returns_id_and_redirect(idp):
    cfg = _cfg_with_cert(idp)
    request_id, location = S.build_authn_request(cfg, idp.metadata_xml)
    assert request_id and location.startswith(SSO_URL)
    assert "SAMLRequest=" in location


@requires_pysaml2
def test_happy_path_validates_and_extracts(idp):
    cfg = _cfg_with_cert(idp, email_attr="mail")
    request_id, _ = S.build_authn_request(cfg, idp.metadata_xml)
    resp = idp.make_response(request_id, email="alice@corp.test", roles=("soc-admins",))

    assertion = S.parse_response(
        cfg, idp.metadata_xml, saml_response=resp, outstanding={request_id: ACS}
    )
    assert assertion.name_id == "alice@corp.test"
    assert assertion.in_response_to == request_id
    assert S.extract_email(assertion, cfg) == "alice@corp.test"
    assert S.map_role(cfg, S.extract_roles(assertion, cfg)) == "admin"


@requires_pysaml2
def test_unsigned_assertion_rejected(idp):
    cfg = _cfg_with_cert(idp)
    request_id, _ = S.build_authn_request(cfg, idp.metadata_xml)
    resp = idp.make_response(request_id, sign=False)
    with pytest.raises(S.SAMLError):
        S.parse_response(cfg, idp.metadata_xml, saml_response=resp, outstanding={request_id: ACS})


@requires_pysaml2
def test_tampered_signature_rejected(idp):
    cfg = _cfg_with_cert(idp)
    request_id, _ = S.build_authn_request(cfg, idp.metadata_xml)
    resp = idp.make_response(request_id, email="alice@corp.test")
    # Flip a byte inside the signed assertion (the email attribute value).
    raw = base64.b64decode(resp).decode()
    tampered = raw.replace("alice@corp.test", "mallory@evil.test")
    bad = base64.b64encode(tampered.encode()).decode()
    with pytest.raises(S.SAMLError):
        S.parse_response(cfg, idp.metadata_xml, saml_response=bad, outstanding={request_id: ACS})


@requires_pysaml2
def test_replayed_or_unknown_inresponseto_rejected(idp):
    cfg = _cfg_with_cert(idp)
    request_id, _ = S.build_authn_request(cfg, idp.metadata_xml)
    resp = idp.make_response(request_id)
    # The AuthnRequest id we issued is NOT in the outstanding map → replay defense.
    with pytest.raises(S.SAMLError):
        S.parse_response(
            cfg, idp.metadata_xml, saml_response=resp, outstanding={"some-other-id": ACS}
        )


@requires_pysaml2
def test_wrong_audience_rejected(idp):
    # Assertion is minted for SP_ENTITY; parse it as a DIFFERENT SP entity id.
    cfg_real = _cfg_with_cert(idp)
    request_id, _ = S.build_authn_request(cfg_real, idp.metadata_xml)
    resp = idp.make_response(request_id, audience=SP_ENTITY)

    cfg_other = _cfg_with_cert(idp, sp_entity_id="https://other-sp.test")
    with pytest.raises(S.SAMLError):
        S.parse_response(
            cfg_other, idp.metadata_xml, saml_response=resp, outstanding={request_id: ACS}
        )


@requires_pysaml2
def test_expired_assertion_rejected():
    """An assertion whose Conditions NotOnOrAfter is in the past is rejected."""
    expired_idp = _TestIdP(lifetime_minutes=-5)
    cfg = _cfg(x509cert=expired_idp.cert_pem)
    request_id, _ = S.build_authn_request(cfg, expired_idp.metadata_xml)
    resp = expired_idp.make_response(request_id)
    with pytest.raises(S.SAMLError):
        S.parse_response(
            cfg, expired_idp.metadata_xml, saml_response=resp, outstanding={request_id: ACS}
        )
