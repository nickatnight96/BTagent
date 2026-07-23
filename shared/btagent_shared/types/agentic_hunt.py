"""Agentic-AI Misuse Hunter schemas (Phase 6 #121 — connector-independent slice).

Defines the data contracts for hunting misuse of agentic-AI workloads:
- :class:`PromptInjectionSignal` — a single suspected prompt-injection observation
  on an agent-call input (LLM prompt, tool argument, retrieved-context blob).
- :class:`AgentIdentity` — registration record for an agentic identity (Bedrock
  AgentCore agent, Vertex Agent Engine, Cloud Run MCP server, K8s pod identity,
  or an unmanaged compute role with LLM SDK calls) capturing the *declared*
  toolset / capabilities so behavioural divergence can be flagged.
- :class:`AgentCallEvent` — the per-invocation telemetry tuple the detectors
  consume (input excerpt, tool/API the agent actually called, observed identity).

These types are the serialisation layer between:
  * :mod:`btagent_shared.hunt.agentic` (pure detection logic, no network)
  * Future LLM-call telemetry MCP connector (deferred — see the live-wiring TODO
    in :mod:`btagent_shared.hunt.agentic`)
  * The :class:`~btagent_shared.types.cloud_hunt.AgenticWorkload` inventory from
    #117 (reused here for shadow-MCP / shadow-agent discovery so a future
    governance workflow routes cloud + agentic findings through one queue).
  * The #119 HuntFinding triage queue.

Design notes:
- Pydantic v2 with ``extra="forbid"`` — any undeclared field is a schema violation.
- StrEnum values are lowercase, consistent with the rest of btagent_shared.types.
- Zero heavy dependencies (no LangChain, no LiteLLM, no MCP, no network).
- DEFENSIVE-FACING: this module describes the *shape* of attack telemetry the
  detectors operate on. Concrete attack-pattern strings live in
  :mod:`btagent_shared.hunt.agentic` and reference public taxonomies
  (OWASP LLM Top-10, MITRE ATLAS) in comments — not as attack tooling.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Agent identity / capability enumerations
# ---------------------------------------------------------------------------


class AgentIdentityKind(StrEnum):
    """Classification of an agentic identity registration.

    Mirrors :class:`btagent_shared.types.cloud_hunt.AgenticWorkloadKind` but at the
    *identity* (registration) layer rather than the workload (compute) layer.

    ``BEDROCK_AGENT`` — AWS Bedrock AgentCore agent registration.
    ``VERTEX_AGENT`` — Google Vertex AI Agent Engine registration.
    ``CLOUD_RUN_MCP`` — Cloud Run service exposing the MCP protocol.
    ``K8S_AGENT_POD`` — Kubernetes pod running an agent runtime with its own SA.
    ``UNMANAGED`` — Any identity making LLM/tool calls that is not registered in
        a sanctioned agent platform (e.g. an EC2 instance role calling Bedrock
        directly, or a personal API key bridged via a local MCP shim).
    """

    BEDROCK_AGENT = "bedrock_agent"
    VERTEX_AGENT = "vertex_agent"
    CLOUD_RUN_MCP = "cloud_run_mcp"
    K8S_AGENT_POD = "k8s_agent_pod"
    UNMANAGED = "unmanaged"


class PromptInjectionCategory(StrEnum):
    """High-level taxonomy of detected prompt-injection signals.

    Aligned to OWASP LLM01 (Prompt Injection) sub-categories and MITRE ATLAS
    AML.T0051 (LLM Prompt Injection). Detector heuristics in
    :mod:`btagent_shared.hunt.agentic` map matched signatures to one of these.
    """

    INSTRUCTION_OVERRIDE = "instruction_override"  # "ignore previous instructions"
    ROLE_HIJACK = "role_hijack"  # "you are now ...", system-prompt impersonation
    JAILBREAK = "jailbreak"  # DAN-style + sibling jailbreak personae
    ENCODED_PAYLOAD = "encoded_payload"  # base64 / hex blobs embedded in user text
    DATA_EXFIL_REQUEST = "data_exfil_request"  # "print your system prompt" / secret leak
    TOOL_ABUSE_REQUEST = "tool_abuse_request"  # "call delete_all() with arg=..."


# ---------------------------------------------------------------------------
# PromptInjectionSignal
# ---------------------------------------------------------------------------


class PromptInjectionSignal(BaseModel):
    """A single observed prompt-injection signal on an agent call.

    Emitted by :func:`btagent_shared.hunt.agentic.scan_for_prompt_injection` and
    aggregated into a :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest`.

    The ``source_text`` and ``redacted_excerpt`` are kept separate so the
    detection payload can be persisted/quoted in evidence without exposing the
    full untrusted input (which itself may contain secondary injection content
    aimed at downstream readers / log pipelines).
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Stable identifier of the upstream agent-call event.",
    )
    source_text: str = Field(
        default="",
        max_length=16384,
        description=(
            "Raw input that was scanned. May be empty when the source is a tool "
            "argument blob persisted out-of-band; in that case ``redacted_excerpt`` "
            "carries the evidence."
        ),
    )
    redacted_excerpt: str = Field(
        default="",
        max_length=512,
        description=(
            "Short safe-to-log excerpt of the matched region with surrounding bytes "
            "elided. Suitable for inclusion in finding evidence / triage UI."
        ),
    )
    category: PromptInjectionCategory
    injected_pattern: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="The signature label that matched (not the user input).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Match confidence in [0, 1]; combined across signals for the finding.",
    )
    observed_at: datetime = Field(default_factory=datetime.utcnow)
    # Optional pointer back to the agent identity that received the input.
    agent_identity_ref: str | None = Field(
        default=None,
        max_length=512,
        description="Identity reference (ARN / SA email / pod UID) of the receiving agent.",
    )


# ---------------------------------------------------------------------------
# AgentIdentity
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """Registration record for an agentic identity (declared capabilities + tooling).

    Combined with per-invocation :class:`AgentCallEvent` records, this is the
    inventory the *identity-abuse* detector compares observed behaviour against.

    The ``tooling`` field is the **declared** MCP / function-tool catalogue the
    agent was registered with — divergence (a call to an undeclared tool, or an
    API call that resolves to an identity above ``declared_role``) is what the
    detector flags.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=128)
    org_id: str = Field(..., description="Tenant scope.")
    kind: AgentIdentityKind
    # Provider-specific identity reference (ARN, SA email, K8s SA UID, …).
    identity_ref: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Stable identity reference; matches CloudIdentity.arn_or_id when present.",
    )
    display_name: str = Field(default="", max_length=300)
    # Declared capability surface — what the agent is *supposed* to be able to do.
    capabilities: list[str] = Field(
        default_factory=list,
        description=(
            "Declared capability tags (e.g. ['read_knowledge_base', 'create_ticket']). "
            "Free-form labels; the detector matches observed-tool names against this set."
        ),
    )
    # Declared tool catalogue — names of MCP tools / function-tools the agent may invoke.
    tooling: list[str] = Field(
        default_factory=list,
        description="Declared tool / MCP-method names the agent is permitted to call.",
    )
    # Optional: the IAM role/SA the agent is registered to run as. The detector
    # flags calls that resolve to a *different* (typically higher-privilege)
    # role than this declared identity.
    declared_role: str | None = Field(
        default=None,
        max_length=512,
        description="Declared IAM role / SA. Divergence at runtime is suspicious.",
    )
    # Cross-reference to the AgenticWorkload (#117) when discovered via the
    # cloud-side inventory. Letting the agentic hunter reuse #117's shadow flag
    # is the single shared-surface point the issue text calls out.
    workload_ref: str | None = Field(
        default=None,
        max_length=512,
        description="resource_id of the linked AgenticWorkload (#117) when known.",
    )
    governance_tagged: bool = Field(
        default=False,
        description="True when all required governance tags are present on the registration.",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)
    # Free-form enrichment from connector / fixture.
    enrichment: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# AgentCallEvent — per-invocation telemetry
# ---------------------------------------------------------------------------


class AgentCallEvent(BaseModel):
    """One observation of an agent invoking a tool / API.

    Per-call event the detectors traverse to spot prompt-injection inputs and
    identity-abuse behaviour. Sourced from a telemetry MCP connector (deferred)
    or supplied by fixtures in the golden tests.

    ``observed_role`` is the role the underlying API call actually resolved to
    — when this differs from the linked :class:`AgentIdentity`'s
    ``declared_role`` the identity-abuse detector flags the call.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1, max_length=128)
    org_id: str = Field(..., description="Tenant scope.")
    agent_identity_ref: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Identity reference of the agent that issued the call.",
    )
    observed_at: datetime
    # The textual input the agent received (prompt or tool argument). Scanned by
    # the prompt-injection detector. May be empty when the call is purely tool-arg.
    input_text: str = Field(
        default="",
        max_length=16384,
        description="Raw input text the agent received for this invocation.",
    )
    # The textual output the model/tool returned for this invocation. Scanned
    # by the LLM-exfil detector for leaked secrets. Empty when the telemetry
    # source does not capture responses.
    output_text: str = Field(
        default="",
        max_length=16384,
        description="Raw output text the agent produced for this invocation.",
    )
    # What the agent actually did — the API / MCP-tool name and resolved identity.
    invoked_tool: str = Field(
        default="",
        max_length=256,
        description="Name of the tool / MCP-method / API call actually invoked.",
    )
    invoked_api: str | None = Field(
        default=None,
        max_length=256,
        description="Concrete cloud API surfaced behind the tool (e.g. 's3:GetObject').",
    )
    observed_role: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Role/SA the API call resolved to at execution time. "
            "Divergence from the AgentIdentity.declared_role is flagged."
        ),
    )
    # Free-form context from the telemetry source.
    metadata: dict[str, Any] = Field(default_factory=dict)
