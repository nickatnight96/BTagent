"""MCP (Model Context Protocol) types for tool integration."""

from pydantic import BaseModel, Field

from btagent_shared.types.config import MCPTransport


class MCPServerConfig(BaseModel):
    """Configuration for a BTagent MCP server (connector)."""

    name: str
    description: str
    transport: MCPTransport = MCPTransport.STDIO
    command: list[str] | None = None
    server_url: str | None = None
    mock_mode: bool = False
    health_check_interval: int = 60
    max_retries: int = 3
    timeout_seconds: int = 30
    circuit_breaker_threshold: int = 5
    circuit_breaker_recovery: int = 30


class MCPToolInfo(BaseModel):
    """Metadata about a tool exposed by an MCP server."""

    name: str
    description: str
    server_id: str
    input_schema: dict = Field(default_factory=dict)


class MCPConnectionStatus(BaseModel):
    """Runtime status of an MCP connection."""

    connection_id: str
    server_name: str
    status: str  # connected, disconnected, circuit_open, half_open
    last_health_check: str | None = None
    failure_count: int = 0
    active_consumers: int = 0
