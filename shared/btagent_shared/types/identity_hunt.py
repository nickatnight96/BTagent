"""Identity Hunt schemas (Phase 6 #116 — Identity Hunt Agent).

Data contracts for the connector-independent slice of the Identity Hunt Agent.
Live-connector wiring (Okta / Entra ID / Google Workspace MCP, tracked in #100)
is deferred; everything here operates on fixture data or streaming events
supplied by the eventual connectors.

Design notes:
- No heavy deps (this is in the ``shared/`` tier — no DB, MCP, or LLM imports).
- Pydantic v2, ConfigDict(extra="forbid"), lowercase StrEnum values throughout.
- Mirrors the style of :mod:`btagent_shared.types.behavioral`.
- The ``OAuthGrant`` model is the central unit for OAuth-grant-graph detections;
  ``IdentityEvent`` is the generic event feed that detectors consume.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IdentityProvider(StrEnum):
    """Cloud identity provider the entity originates from.

    Mapped 1-to-1 to the connectors in connector-tier #100. The enum exists
    here so fixture tests can run without a live connector.
    """

    OKTA = "okta"
    ENTRA = "entra"
    GOOGLE_WORKSPACE = "google_workspace"
    DUO = "duo"  # Cisco Duo MFA (Tier-2 #100)
    GENERIC = "generic"  # local / on-prem / not yet classified


class IdentityEntityKind(StrEnum):
    """The type of identity subject being tracked."""

    USER = "user"
    SERVICE_PRINCIPAL = "service_principal"
    OAUTH_APP = "oauth_app"
    SESSION = "session"
    DEVICE = "device"


class OAuthConsentType(StrEnum):
    """How the OAuth grant was consented to.

    ``admin`` grants are granted by an admin on behalf of all users;
    ``user`` grants are granted per-user; ``pre_authorized`` bypasses the
    consent dialog entirely (high-risk signal for dormant-app reactivation).
    """

    ADMIN = "admin"
    USER = "user"
    PRE_AUTHORIZED = "pre_authorized"
    UNKNOWN = "unknown"


class IdentityEventKind(StrEnum):
    """The type of identity event ingested from a provider audit log."""

    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOKED = "token_revoked"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_DENIED = "mfa_denied"
    MFA_APPROVED = "mfa_approved"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    CREDENTIAL_ADDED = "credential_added"
    CREDENTIAL_REMOVED = "credential_removed"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    FEDERATION_TRUST_MODIFIED = "federation_trust_modified"
    GRANT_CREATED = "grant_created"
    GRANT_REVOKED = "grant_revoked"
    APP_CONSENT_GRANTED = "app_consent_granted"


# ---------------------------------------------------------------------------
# Core identity entities
# ---------------------------------------------------------------------------


class IdentityEntity(BaseModel):
    """A subject in the identity plane — user, service principal, OAuth app, or session.

    ``canonical_id`` is the stable string used for clustering and suppression
    (e.g. UPN for users, client_id for OAuth apps, session_id for sessions).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    kind: IdentityEntityKind
    provider: IdentityProvider
    canonical_id: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Stable, provider-scoped identifier (UPN, client_id, session token hash, etc.).",
    )
    display_name: str = Field(default="", max_length=300)
    first_seen: datetime
    last_seen: datetime
    enrichment: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# OAuth grant graph
# ---------------------------------------------------------------------------


class OAuthGrant(BaseModel):
    """One OAuth permission grant in the principal↔app grant graph.

    Represents a scope bundle granted to an ``app_id`` (client) on behalf of
    a ``principal_id`` (user or service account). The grant graph is built
    from provider audit logs by :mod:`btagent_shared.hunt.identity`.

    Fields map to the common OAuth 2.0 / OIDC concepts that Okta, Entra,
    and Google Workspace all expose (names differ but semantics align).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    app_id: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Client / application ID that holds this grant (OAuth client_id).",
    )
    app_display_name: str = Field(default="", max_length=300)
    principal_id: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="User or service account UPN / object_id the grant was consented for.",
    )
    provider: IdentityProvider
    scopes: list[str] = Field(
        default_factory=list,
        description="Normalised OAuth scope strings (e.g. 'Mail.Read', 'offline_access').",
    )
    consent_type: OAuthConsentType = OAuthConsentType.UNKNOWN
    granted_at: datetime
    last_used: datetime | None = None
    # ``revoked_at`` is None while the grant is active.
    revoked_at: datetime | None = None
    # Enrichment blob — provider raw payload for forensics.
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generic identity event (detector input)
# ---------------------------------------------------------------------------


class GeoLocation(BaseModel):
    """Coarse geolocation attached to a sign-in / token event."""

    model_config = ConfigDict(extra="forbid")

    country: str = Field(default="", max_length=64)
    city: str = Field(default="", max_length=128)
    latitude: float | None = None
    longitude: float | None = None
    asn: str = Field(
        default="",
        max_length=32,
        description="Autonomous System Number (e.g. 'AS15169') for ASN-diversity checks.",
    )


class IdentityEvent(BaseModel):
    """A single event from a provider audit log.

    Detectors in :mod:`btagent_shared.hunt.identity` operate on lists of
    these to decide whether to emit a :class:`IdentityDetectionResult`.

    The ``session_id`` / ``token_id`` fields enable token-replay and
    MFA-fatigue correlations across events from the same credential.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    org_id: str = Field(..., min_length=1, max_length=200)
    provider: IdentityProvider
    kind: IdentityEventKind
    principal_id: str = Field(..., min_length=1, max_length=512)
    app_id: str = Field(default="", max_length=512)
    session_id: str = Field(
        default="",
        max_length=512,
        description="Session or refresh-token ID; used for token-replay correlation.",
    )
    token_id: str = Field(
        default="",
        max_length=512,
        description="Access-token ID / jti; used for token-replay replay detection.",
    )
    ip_address: str = Field(default="", max_length=64)
    geo: GeoLocation = Field(default_factory=GeoLocation)
    user_agent: str = Field(default="", max_length=512)
    timestamp: datetime
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Detector output — maps 1:1 to a RecordFindingRequest
# ---------------------------------------------------------------------------


class IdentityDetectionResult(BaseModel):
    """Structured output of a single identity detector run.

    Each result carries enough information to build a
    :class:`btagent_shared.types.hunt_finding.RecordFindingRequest`
    (source=identity, domain=identity) without any further enrichment.
    The mapping function lives in :mod:`btagent_shared.hunt.identity`.
    """

    model_config = ConfigDict(extra="forbid")

    detection_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Unique ID for this detection hit (deterministic or ULID).",
    )
    rule_id: str = Field(..., min_length=1, max_length=200)
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field(default="", max_length=8192)
    # Severity string matches btagent_shared.types.enums.Severity values.
    severity: str = Field(default="medium")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    technique_ids: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs implicated (e.g. ['T1550.001', 'T1078']).",
    )
    # Entities + observables match the hunt_finding contract.
    entity_kind: str = Field(default="user", max_length=64)
    entity_value: str = Field(default="", max_length=512)
    observable_type: str = Field(default="", max_length=64)
    observable_value: str = Field(default="", max_length=2048)
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Provenance — event IDs, timestamps, geo details, etc.",
    )


# ---------------------------------------------------------------------------
# Revocation proposal (#116 Phase C) — confirmed hit → revoke-playbook (HITL)
# ---------------------------------------------------------------------------


class RevocationProposalStatus(StrEnum):
    """Lifecycle of a revoke-playbook proposal attached to an investigation."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class RevocationTarget(BaseModel):
    """One (principal, app) grant slated for revocation.

    Deduped by ``(provider, principal_id, app_id)`` — several findings about
    the same grant collapse into one target carrying every source finding ID.
    """

    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(..., min_length=1, max_length=512)
    app_id: str = Field(..., min_length=1, max_length=512)
    provider: IdentityProvider
    app_display_name: str = Field(default="", max_length=300)
    scopes: list[str] = Field(default_factory=list)
    source_finding_ids: list[str] = Field(default_factory=list)


class RevocationProposal(BaseModel):
    """A revoke-playbook proposal generated when identity grant findings are
    promoted to an investigation.

    The proposal is *inert data* until a senior analyst accepts it (the HITL
    gate): acceptance materialises ``playbook_spec`` as a real SOAR playbook
    whose own first step is a second ``hitl_gate`` guarding execution.
    ``playbook_spec`` is the playbook as a JSON-safe dict — the backend dumps
    it to YAML for the playbook service on accept.
    """

    model_config = ConfigDict(extra="forbid")

    targets: list[RevocationTarget]
    rationale: str = Field(default="", max_length=8192)
    playbook_name: str = Field(..., min_length=1, max_length=300)
    playbook_spec: dict[str, Any]
    status: RevocationProposalStatus = RevocationProposalStatus.PROPOSED
    # Set on accept — the materialised playbook's ID.
    playbook_id: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_rationale: str = Field(default="", max_length=8192)
