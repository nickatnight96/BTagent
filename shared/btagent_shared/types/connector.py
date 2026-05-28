"""Connector manifest schema — capability self-description for integration nodes.

Implements Layer 3 of the connector strategy in #100: every integration
node declares a structured manifest of what it can do (queries, actions,
streams), what each capability emits in OCSF terms, what credentials it
needs, and what runtime policy applies (HITL, TLP egress, cost class).

The manifest is what lets the engine:

* **Auto-gate** any ``hitl_required=True`` action through HITLMiddleware
  without per-node policy code.
* **Route** sensitive outputs away from cloud LLMs based on the
  declared TLP-egress class.
* **Estimate cost** before executing a multi-step hunt by summing
  ``cost_class`` across all queries.
* **Plan** ("what tools can deactivate a user?") via manifest
  introspection rather than name-string matching.
* **Detect schema drift** by comparing declared OCSF event classes
  against actual node outputs.

Design notes (pin these to avoid drift):

1. **Pydantic-only.** No engine imports. Lives in shared/ so backend +
   frontend + agents can introspect manifests without pulling the engine.
2. **OCSF v1.4 alignment.** The OCSFEventClass enum is a curated subset
   of the [OCSF v1.4 event classes](https://schema.ocsf.io) that map
   cleanly onto security-tool capabilities. Add new ones here as the
   connector catalog grows.
3. **Capability id is stable.** Workflows reference a capability by its
   ``manifest.name + capability.id`` (e.g. ``okta.deactivate_user``);
   renaming a shipped capability breaks existing workflows.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import TLP

# ---------------------------------------------------------------------------
# OCSF — Open Cybersecurity Schema Framework v1.4 (curated subset)
# ---------------------------------------------------------------------------


class OCSFEventClass(StrEnum):
    """Curated subset of OCSF v1.4 event classes.

    Names match the OCSF taxonomy (e.g. ``authentication``,
    ``process_activity``); use the OCSF docs as the source of truth for
    field semantics. Add classes here as new connector capabilities
    require them — do not invent off-spec class names.
    """

    # System Activity (1xxx)
    PROCESS_ACTIVITY = "process_activity"
    FILE_ACTIVITY = "file_activity"
    KERNEL_ACTIVITY = "kernel_activity"
    MEMORY_ACTIVITY = "memory_activity"
    MODULE_ACTIVITY = "module_activity"

    # Findings (2xxx)
    DETECTION_FINDING = "detection_finding"
    VULNERABILITY_FINDING = "vulnerability_finding"
    COMPLIANCE_FINDING = "compliance_finding"
    INCIDENT_FINDING = "incident_finding"

    # IAM (3xxx)
    AUTHENTICATION = "authentication"
    AUTHORIZE_SESSION = "authorize_session"
    ENTITY_MANAGEMENT = "entity_management"
    USER_INVENTORY = "user_inventory"
    GROUP_MANAGEMENT = "group_management"

    # Network (4xxx)
    NETWORK_ACTIVITY = "network_activity"
    HTTP_ACTIVITY = "http_activity"
    DNS_ACTIVITY = "dns_activity"
    EMAIL_ACTIVITY = "email_activity"
    SSH_ACTIVITY = "ssh_activity"
    NTP_ACTIVITY = "ntp_activity"

    # Discovery (5xxx)
    DEVICE_INVENTORY = "device_inventory"
    DEVICE_CONFIG_STATE = "device_config_state"

    # Audit / Application (6xxx)
    AUDIT_ACTIVITY = "audit_activity"
    API_ACTIVITY = "api_activity"
    APPLICATION_LIFECYCLE = "application_lifecycle"
    DATABASE_ACTIVITY = "database_activity"

    # Threat intelligence
    THREAT_INTELLIGENCE = (
        "threat_intelligence"  # not strictly an OCSF class, but consistent terminology
    )


# ---------------------------------------------------------------------------
# Capability classification axes
# ---------------------------------------------------------------------------


class CredentialType(StrEnum):
    """How a connector authenticates. Mirrors the n8n credential-type
    pattern (#101): the manifest declares the type, the per-org
    credential record stores the encrypted material.
    """

    NONE = "none"  # public endpoints (rare)
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    BASIC = "basic"
    AWS_SIGV4 = "aws_sigv4"
    MTLS = "mtls"
    BEARER = "bearer"
    CUSTOM = "custom"  # vendor-specific (e.g. CrowdStrike API key + secret pair)


class TransportKind(StrEnum):
    """How the engine reaches the connector."""

    MCP_STDIO = "mcp/stdio"
    MCP_HTTP = "mcp/http"
    MCP_SSE = "mcp/sse"
    MCP_WEBSOCKET = "mcp/websocket"
    HTTP_REST = "http/rest"  # declarative HTTP, no MCP server
    HTTP_GRAPHQL = "http/graphql"
    NATIVE = "native"  # Python SDK direct (legacy / last resort)


class CostClass(StrEnum):
    """Rough cost bucket for capability planning.

    ``cheap``: read-only, sub-second, no per-call fee (a SIEM count
    query, a CMDB lookup).
    ``moderate``: read-only but pricey (a 30-day Splunk hunt, a
    VirusTotal Premium API call).
    ``expensive``: writes, multi-second, billed (an EDR scan, a
    forensic snapshot).
    """

    CHEAP = "cheap"
    MODERATE = "moderate"
    EXPENSIVE = "expensive"


class BlastRadius(StrEnum):
    """For action capabilities — how widely the effect propagates."""

    NONE = "none"  # action is a no-op or read-only
    SINGLE_USER = "single_user"
    SINGLE_HOST = "single_host"
    SUBNET = "subnet"
    ORG = "org"
    GLOBAL = "global"  # network-wide block, default-deny, etc.


# ---------------------------------------------------------------------------
# Capability shapes
# ---------------------------------------------------------------------------


class _CapabilityBase(BaseModel):
    """Fields shared across all three capability kinds (query / action / stream)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        ...,
        description="Stable identifier within the connector. "
        "Workflow files reference capabilities as <connector>.<capability_id> "
        "(e.g. 'okta.search_audit_log'). Renaming breaks existing workflows.",
    )
    description: str = Field(default="", description="Human-readable purpose.")
    ocsf_emits: list[OCSFEventClass] = Field(
        default_factory=list,
        description="OCSF event classes this capability's output can contain. "
        "Empty for capabilities that don't emit OCSF-shaped data (e.g. a "
        "raw-metadata lookup that callers must transform first).",
    )
    tlp_egress: TLP = Field(
        default=TLP.GREEN,
        description="Maximum TLP level this capability is allowed to egress data at. "
        "Combined with the runtime classification, governs whether the result "
        "can flow to cloud LLMs.",
    )
    cost_class: CostClass = Field(default=CostClass.CHEAP)
    hitl_required: bool = Field(
        default=False,
        description="If True, the HITLMiddleware blocks execution until "
        "an analyst approves. Defaults to False for queries; almost always True for actions.",
    )


class QueryCapability(_CapabilityBase):
    """A read-only capability — fetches data without changing remote state."""

    kind: Literal["query"] = "query"
    count_only_supported: bool = Field(
        default=False,
        description="True if the capability can be invoked in count-only mode "
        "(returns hit count without enumerating results). Used by the "
        "NoiseBaseline node (#99 Phase B) to estimate query volume.",
    )


class ActionCapability(_CapabilityBase):
    """A capability that changes remote state — defaults to HITL-required.

    The default ``hitl_required=True`` is deliberate: any mutate-action
    must be gated unless the connector author explicitly opts out
    (which would require sign-off via the manifest review).
    """

    kind: Literal["action"] = "action"
    hitl_required: bool = Field(default=True)
    reversible: bool = Field(
        default=False,
        description="True if the action can be undone via another capability. "
        "Surfaces in the UI ('this action is reversible') and gates the "
        "auto-generated rollback plan.",
    )
    blast_radius: BlastRadius = Field(default=BlastRadius.SINGLE_USER)


class StreamCapability(_CapabilityBase):
    """A capability that subscribes to a continuous event stream from the connector."""

    kind: Literal["stream"] = "stream"
    transport: Literal["webhook", "polling", "websocket"] = "webhook"


# ---------------------------------------------------------------------------
# Top-level manifest
# ---------------------------------------------------------------------------


class ConnectorManifest(BaseModel):
    """Connector self-description.

    Attached as a ``ClassVar`` on integration Node subclasses so the
    runtime can introspect capability metadata before execution.

    Bump ``version`` whenever you change capability semantics in a way
    a workflow author would care about (added required input field,
    renamed an OCSF mapping, raised the TLP-egress default). Pure
    additive changes (new optional fields, new capabilities) only need
    a minor-version bump.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        description="Connector identifier (e.g. 'splunk', 'okta', 'virustotal'). "
        "Matches the integration node file name and is what workflow "
        "files reference.",
    )
    version: str = Field(
        ...,
        description="Manifest semver. Bump on capability-semantics changes.",
    )
    description: str = Field(default="", description="One-line connector summary.")
    transport: TransportKind = Field(...)
    auth: CredentialType = Field(...)

    queries: list[QueryCapability] = Field(default_factory=list)
    actions: list[ActionCapability] = Field(default_factory=list)
    streams: list[StreamCapability] = Field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Introspection helpers
    # ------------------------------------------------------------------ #

    def capability(
        self, capability_id: str
    ) -> QueryCapability | ActionCapability | StreamCapability | None:
        """Look up a capability by its id across all three kinds."""
        for cap in (*self.queries, *self.actions, *self.streams):
            if cap.id == capability_id:
                return cap
        return None

    def capabilities_emitting(
        self, ocsf_class: OCSFEventClass
    ) -> list[QueryCapability | ActionCapability | StreamCapability]:
        """All capabilities that emit a given OCSF event class.

        Used by planners to answer "what tool can give me
        ``authentication`` events?" without name-matching.
        """
        return [
            cap
            for cap in (*self.queries, *self.actions, *self.streams)
            if ocsf_class in cap.ocsf_emits
        ]


__all__ = [
    "ActionCapability",
    "BlastRadius",
    "ConnectorManifest",
    "CostClass",
    "CredentialType",
    "OCSFEventClass",
    "QueryCapability",
    "StreamCapability",
    "TransportKind",
]
