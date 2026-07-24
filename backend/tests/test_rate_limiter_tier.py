"""Regression tests for GH #378 — rate-limit tier must come from a VERIFIED token.

The rate limiter used to read the role tier from a *signature-less* base64
decode of the JWT payload, so an attacker could send
``Authorization: Bearer x.<b64 {"role":"admin"}>.x`` and be handed the admin
rate-limit tier with no valid token. These tests pin the fix: the tier is now
derived only from a token that passes the project's real verifier
(:func:`btagent_backend.auth.jwt.decode_token`), and anything unverifiable
degrades to the anonymous tier without raising.
"""

import base64
import json
from types import SimpleNamespace

from btagent_backend.auth.cookies import ACCESS_COOKIE_NAME
from btagent_backend.auth.jwt import create_access_token
from btagent_backend.middleware.rate_limiter import (
    DEFAULT_LIMIT,
    ROLE_LIMITS,
    _client_key,
    _extract_role,
    _verified_payload,
)


def _make_request(*, authorization=None, cookies=None, host="203.0.113.7"):
    """Build a minimal stand-in for a Starlette ``Request``.

    ``_verified_payload`` / ``_client_key`` only touch ``.cookies``, ``.headers``
    and ``.client``, so a light namespace is enough and keeps the test free of
    ASGI-scope boilerplate.
    """
    headers = {}
    if authorization is not None:
        headers["authorization"] = authorization
    client = SimpleNamespace(host=host) if host is not None else None
    return SimpleNamespace(headers=headers, cookies=cookies or {}, client=client)


def _forge_bearer(role: str = "admin") -> str:
    """Craft the attack token: ``x.<b64 {"role": role, "type": "access"}>.x``.

    Header and signature segments are garbage; only the middle (payload) segment
    is real base64. The old code trusted it; the new code must reject it because
    the signature does not verify.
    """
    body = (
        base64.urlsafe_b64encode(
            json.dumps({"sub": "attacker", "role": role, "type": "access"}).encode()
        )
        .decode()
        .rstrip("=")
    )
    return f"x.{body}.x"


# ---------------------------------------------------------------------------
# (a) Forged admin token (bad signature) -> anonymous tier, NOT admin.
# ---------------------------------------------------------------------------


def test_forged_admin_bearer_is_treated_as_anonymous():
    req = _make_request(authorization=f"Bearer {_forge_bearer('admin')}")

    payload = _verified_payload(req)
    assert payload is None  # signature never verified -> no trusted claims

    role = _extract_role(payload)
    assert role == "anonymous"
    # Crucially, the attacker does NOT get the admin tier.
    assert ROLE_LIMITS.get(role, DEFAULT_LIMIT) == DEFAULT_LIMIT
    assert ROLE_LIMITS.get(role, DEFAULT_LIMIT) != ROLE_LIMITS["admin"]

    # And the forged request is keyed by IP, not by the forged subject.
    assert _client_key(req, payload) == "ip:203.0.113.7"


# ---------------------------------------------------------------------------
# (b) Genuinely signed admin token -> admin tier + verified-subject keying.
# ---------------------------------------------------------------------------


def test_genuine_admin_token_gets_admin_tier():
    token, _jti = create_access_token("usr_admin_1", "real_admin", "admin")

    # Header transport.
    req = _make_request(authorization=f"Bearer {token}")
    payload = _verified_payload(req)
    assert payload is not None
    assert payload.type == "access"

    role = _extract_role(payload)
    assert role == "admin"
    assert ROLE_LIMITS.get(role, DEFAULT_LIMIT) == ROLE_LIMITS["admin"]

    # Authenticated requests key by the verified subject, not the client IP.
    assert _client_key(req, payload) == "user:usr_admin_1"


def test_genuine_admin_token_via_cookie_gets_admin_tier():
    """The dual-read transport also honours the httpOnly access cookie."""
    token, _jti = create_access_token("usr_admin_2", "cookie_admin", "admin")

    req = _make_request(cookies={ACCESS_COOKIE_NAME: token})
    payload = _verified_payload(req)
    assert payload is not None
    assert _extract_role(payload) == "admin"
    assert _client_key(req, payload) == "user:usr_admin_2"


def test_genuine_analyst_token_gets_analyst_tier():
    token, _jti = create_access_token("usr_analyst_1", "real_analyst", "analyst")

    req = _make_request(authorization=f"Bearer {token}")
    payload = _verified_payload(req)
    assert payload is not None
    assert _extract_role(payload) == "analyst"
    assert ROLE_LIMITS.get(_extract_role(payload), DEFAULT_LIMIT) == ROLE_LIMITS["analyst"]


# ---------------------------------------------------------------------------
# (c) Malformed / garbage headers degrade to anonymous without raising.
# ---------------------------------------------------------------------------


def test_garbage_bearer_degrades_to_anonymous_without_raising():
    for bad in (
        "Bearer not-a-jwt",
        "Bearer x.y.z",
        "Bearer ....",
        "Bearer ",
        "Basic dXNlcjpwYXNz",  # not a bearer scheme at all
        "totally malformed header value",
    ):
        req = _make_request(authorization=bad)
        # Must not raise.
        payload = _verified_payload(req)
        assert payload is None
        assert _extract_role(payload) == "anonymous"
        assert _client_key(req, payload) == "ip:203.0.113.7"


def test_missing_authorization_is_anonymous():
    req = _make_request()  # no header, no cookie
    payload = _verified_payload(req)
    assert payload is None
    assert _extract_role(payload) == "anonymous"
    assert _client_key(req, payload) == "ip:203.0.113.7"


def test_unknown_client_host_keys_gracefully():
    req = _make_request(host=None)  # request.client is None
    assert _client_key(req, None) == "ip:unknown"


def test_refresh_token_type_does_not_confer_a_tier():
    """A non-``access`` token (valid signature, wrong type) is still anonymous."""
    from btagent_backend.auth.jwt import create_refresh_token

    token, _jti, _fid = create_refresh_token("usr_admin_3", "refresh_admin", "admin")
    req = _make_request(authorization=f"Bearer {token}")

    payload = _verified_payload(req)
    assert payload is None  # type != "access" -> rejected
    assert _extract_role(payload) == "anonymous"
