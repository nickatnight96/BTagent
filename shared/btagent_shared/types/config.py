"""Configuration types for BTagent agents and LLM routing."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TLP(StrEnum):
    """Traffic Light Protocol classification levels."""

    RED = "red"  # Named recipients only — on-prem LLM only
    AMBER_STRICT = "amber_strict"  # Organization only — on-prem or trusted cloud
    AMBER = "amber"  # Organization + clients — private cloud allowed
    GREEN = "green"  # Community — any provider
    WHITE = "white"  # Public — any provider, most capable model


class AutonomyLevel(StrEnum):
    """Human-in-the-loop autonomy levels per integration."""

    L0_MANUAL = "L0"  # Every action requires approval
    L1_ASSISTED = "L1"  # Human approves plans, agent executes
    L2_SUPERVISED = "L2"  # Agent executes, human reviews critical decisions
    L3_AUTONOMOUS = "L3"  # Agent runs independently, escalates on issues
    L4_FULL_AUTO = "L4"  # Fully autonomous (scheduled tasks)


class ModelProvider(StrEnum):
    """Supported LLM providers via LiteLLM."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    VERTEX_AI = "vertex_ai"
    AZURE = "azure"
    BEDROCK = "bedrock"
    OLLAMA = "ollama"


class ModelTier(StrEnum):
    """Model capability tiers for task-appropriate routing."""

    FAST = "fast"  # Haiku, GPT-4o-mini, Gemini Flash — triage, classification
    STANDARD = "standard"  # Sonnet, GPT-4o, Gemini Pro — query gen, analysis
    PREMIUM = "premium"  # Opus, o3, Gemini Ultra — complex reasoning
    LOCAL = "local"  # Ollama — sensitive/TLP:RED data


class MCPTransport(StrEnum):
    """MCP connection transport types."""

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"


class MCPConnection(BaseModel):
    """Configuration for an MCP server connection."""

    id: str
    transport: MCPTransport = MCPTransport.STDIO
    command: list[str] | None = None
    server_url: str | None = None
    headers: dict[str, str] | None = None
    env: dict[str, str] = Field(default_factory=dict)
    allowed_tools: list[str] = Field(default_factory=list)
    timeout_seconds: int = 30


class AgentConfig(BaseModel):
    """Configuration passed to agent orchestrator for an investigation."""

    investigation_id: str
    model_provider: ModelProvider = ModelProvider.ANTHROPIC
    model_id: str = "claude-sonnet-4-20250514"
    model_tier: ModelTier = ModelTier.STANDARD
    tlp_level: TLP = TLP.GREEN
    autonomy_level: AutonomyLevel = AutonomyLevel.L2_SUPERVISED
    max_steps: int = 50
    max_tokens: int = 80_000
    max_cost_usd: float = 5.0
    template: str | None = None
    mcp_connections: list[MCPConnection] = Field(default_factory=list)
    org_profile: dict[str, Any] = Field(default_factory=dict)
    mock_connectors: bool = False


class IntegrationAutonomy(BaseModel):
    """Per-integration autonomy level overrides."""

    siem_query: AutonomyLevel = AutonomyLevel.L3_AUTONOMOUS
    edr_query: AutonomyLevel = AutonomyLevel.L3_AUTONOMOUS
    cti_lookup: AutonomyLevel = AutonomyLevel.L3_AUTONOMOUS
    host_isolation: AutonomyLevel = AutonomyLevel.L1_ASSISTED
    firewall_rule: AutonomyLevel = AutonomyLevel.L1_ASSISTED
    account_disable: AutonomyLevel = AutonomyLevel.L0_MANUAL
    playbook_execution: AutonomyLevel = AutonomyLevel.L2_SUPERVISED
