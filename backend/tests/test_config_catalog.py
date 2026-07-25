"""Tests for the configuration inventory (#418 slice 1).

Covers the drift lock (every ``Settings`` field appears in the deploy-time
catalog), secret redaction (credential-bearing fields never expose values),
the runtime-surface inventory shape, and the RBAC gate on
``GET /api/v1/config/schema``.
"""

from conftest import auth_header

from btagent_backend.config import Settings, get_settings
from btagent_backend.services.config_catalog import (
    RUNTIME_SURFACES,
    build_config_catalog,
    deploy_time_entries,
)

URL = "/api/v1/config/schema"

# Fields that MUST be redacted — extend when new credential knobs land.
_MUST_REDACT = {
    "jwt_secret",
    "webhook_secret",
    "s3_secret_key",
    "s3_access_key",
    "mfa_secret_enc_key",
    "database_url",
    "redis_url",
    "oidc_providers",
    "saml_providers",
}


def test_every_settings_field_is_cataloged():
    """Drift lock: adding a Settings knob automatically catalogs it."""
    entries = deploy_time_entries(get_settings())
    cataloged = {e["field"] for e in entries}
    assert cataloged == set(Settings.model_fields.keys())
    # Env names carry the BTAGENT_ prefix.
    by_field = {e["field"]: e for e in entries}
    assert by_field["jwt_secret"]["env"] == "BTAGENT_JWT_SECRET"


def test_sensitive_values_are_redacted():
    entries = {e["field"]: e for e in deploy_time_entries(get_settings())}
    for field in _MUST_REDACT:
        assert entries[field]["sensitive"] is True, field
        assert entries[field]["value"] is None, field
    # Non-sensitive values pass through, and TTL knobs containing "token"
    # in the name are NOT false-positived as secrets.
    assert entries["env"]["value"] == get_settings().env
    assert entries["access_token_ttl_minutes"]["sensitive"] is False
    assert entries["access_token_ttl_minutes"]["value"] == (get_settings().access_token_ttl_minutes)


def test_runtime_surfaces_shape():
    keys = {s["key"] for s in RUNTIME_SURFACES}
    assert {
        "org_profile",
        "tlp_policies",
        "connector_credentials",
        "notification_prefs",
        "dashboard_layout",
        "mfa",
        "data_retention",
        "autonomy",
    } <= keys
    for surface in RUNTIME_SURFACES:
        assert surface["scope"] in ("org", "user", "global"), surface["key"]

    catalog = build_config_catalog(get_settings())
    assert catalog["runtime"] is RUNTIME_SURFACES
    assert len(catalog["deploy_time"]) == len(Settings.model_fields)


async def test_schema_endpoint_redacts_and_requires_auth(client, analyst_token):
    resp = await client.get(URL, headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert {s["key"] for s in data["runtime"]} >= {"org_profile", "tlp_policies"}
    by_field = {e["field"]: e for e in data["deploy_time"]}
    assert by_field["jwt_secret"]["value"] is None
    assert by_field["database_url"]["value"] is None
    # The serialized payload never contains the actual JWT secret anywhere.
    assert get_settings().jwt_secret not in resp.text

    unauth = await client.get(URL)
    assert unauth.status_code == 401
