"""Configuration inventory for the Settings / Configuration Center (#418).

Answers "what can I change, and where?" in one machine-readable place:

* ``RUNTIME_SURFACES`` — the hand-curated inventory of runtime-changeable
  configuration surfaces (DB-backed, editable in-app through an existing
  API/UI), each tagged with its scope and write permission.
* ``deploy_time_entries`` — introspection over the pydantic ``Settings``
  model: every ``BTAGENT_*`` env knob with its type, whether the current
  value differs from the default, and the effective value — REDACTED for
  anything secret-bearing. Values never include raw secrets; credential
  material stays in Vault/AWS/env per the ``${secret:...}`` pattern.

Read-only metadata by design: the catalog describes configuration, it never
mutates it. Served by ``GET /api/v1/config/schema``.
"""

from __future__ import annotations

from typing import Any

from btagent_backend.config import Settings

# Field-name fragments that mark a deploy-time value as secret-bearing.
# Deliberately NOT plain "token"/"key" — TTL knobs like
# ``access_token_ttl_minutes`` and non-credential names would false-positive.
_SENSITIVE_FRAGMENTS = ("secret", "password", "api_key", "enc_key", "access_key")

# Fields whose *values* can embed credentials or per-provider secrets even
# though the name alone doesn't say so (DSNs with userinfo, SSO provider
# configs carrying client_secret).
_SENSITIVE_FIELDS = frozenset({"database_url", "redis_url", "oidc_providers", "saml_providers"})

# Runtime-changeable configuration surfaces. Each already has its own
# API/UI/permission — the catalog consolidates the map, it doesn't replace
# the underlying routes.
RUNTIME_SURFACES: list[dict[str, Any]] = [
    {
        "key": "org_profile",
        "title": "Organization Profile",
        "description": "Industry, compliance frameworks, tech stack, IR team and shifts — injected into agent prompts.",
        "scope": "org",
        "write_permission": "config:org_profile",
        "api": "/api/v1/config/org-profile",
        "ui": "/settings",
    },
    {
        "key": "tlp_policies",
        "title": "TLP & Egress Policies",
        "description": "CISO-approved TLP egress allow/deny exceptions enforced at the MCP dispatch gate.",
        "scope": "org",
        "write_permission": "policy:manage",
        "api": "/api/v1/tlp-policies",
        "ui": "/settings/tlp",
    },
    {
        "key": "connector_credentials",
        "title": "Connector Credentials",
        "description": "Per-org credential references for SIEM/EDR/identity/cloud connectors (references only; raw material stays in Vault/AWS/env).",
        "scope": "org",
        "write_permission": "credential:manage",
        "api": "/api/v1/credentials",
        "ui": "/settings/integrations",
    },
    {
        "key": "notification_prefs",
        "title": "Notification Preferences",
        "description": "Per-user muted in-app notification types, enforced at the send_inapp chokepoint.",
        "scope": "user",
        "write_permission": None,  # self-scoped
        "api": "/api/v1/notifications/preferences",
        "ui": "(notification bell dropdown)",
    },
    {
        "key": "dashboard_layout",
        "title": "PunchList Dashboard Layout",
        "description": "Per-user PunchList arrangement (section visibility, default status filter) with role-tuned defaults.",
        "scope": "user",
        "write_permission": None,  # self-scoped
        "api": "/api/v1/config/dashboard-layout",
        "ui": "/ (PunchList view settings)",
    },
    {
        "key": "mfa",
        "title": "Multi-Factor Authentication",
        "description": "Opt-in TOTP enrollment and recovery codes.",
        "scope": "user",
        "write_permission": None,  # self-scoped
        "api": "/api/v1/mfa",
        "ui": "/settings/mfa",
    },
    {
        "key": "feature_flags",
        "title": "Feature Flags",
        "description": "Per-org boolean capability toggles (wholesale-replace PUT; keys are lowercase snake_case).",
        "scope": "org",
        "write_permission": "config:edit",
        "api": "/api/v1/config/feature-flags",
        "ui": "/config",
    },
    {
        "key": "data_retention",
        "title": "Data Retention",
        "description": "Retention statistics and manual cleanup runs (event/investigation archival, audit verification).",
        "scope": "global",
        "write_permission": "config:edit",
        "api": "/api/v1/config/retention",
        "ui": "/settings",
    },
    {
        "key": "autonomy",
        "title": "Autonomy & HITL Gates",
        "description": "Per-category autonomy levels (L0–L4) governing which agent actions pause for human approval. Read-only surface today (defaults; containment always HITL-gated in code); in-app editing is the #418 follow-up.",
        "scope": "org",
        "write_permission": "config:edit",
        "api": "/api/v1/config/autonomy",  # read-only; editing is the follow-up
        "ui": "/config",
    },
]


def _is_sensitive(field_name: str) -> bool:
    if field_name in _SENSITIVE_FIELDS:
        return True
    return any(fragment in field_name for fragment in _SENSITIVE_FRAGMENTS)


def _type_label(annotation: Any) -> str:
    if annotation is None:
        return "unknown"
    name = getattr(annotation, "__name__", None)
    return name if name is not None else str(annotation)


def deploy_time_entries(settings: Settings) -> list[dict[str, Any]]:
    """One catalog entry per ``Settings`` field (every ``BTAGENT_*`` knob).

    Sensitive entries carry ``value: None`` and ``set`` (whether the
    effective value differs from the field default) so an operator can see
    *that* a secret is configured without ever seeing it.
    """
    defaults = Settings.model_construct()  # field defaults, no env, no validators
    prefix = Settings.model_config.get("env_prefix", "")

    entries: list[dict[str, Any]] = []
    for name, field in type(settings).model_fields.items():
        current = getattr(settings, name)
        default = getattr(defaults, name, field.default)
        sensitive = _is_sensitive(name)
        entries.append(
            {
                "field": name,
                "env": f"{prefix}{name}".upper(),
                "type": _type_label(field.annotation),
                "sensitive": sensitive,
                # Non-sensitive values are safe to display; sensitive ones are
                # redacted and only their configured-ness is surfaced.
                "value": None if sensitive else _display_value(current),
                "is_default": current == default,
            }
        )
    return entries


def _display_value(value: Any) -> Any:
    """JSON-safe rendering for catalog values (models → their dumps)."""
    if isinstance(value, dict):
        return {k: _display_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_display_value(v) for v in value]
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def build_config_catalog(settings: Settings) -> dict[str, Any]:
    """The full inventory: runtime surfaces + deploy-time env knobs."""
    return {
        "runtime": RUNTIME_SURFACES,
        "deploy_time": deploy_time_entries(settings),
    }
