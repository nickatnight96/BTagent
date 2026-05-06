"""MCP transport hardening configuration.

This module extends the base :class:`btagent_shared.types.mcp.MCPServerConfig`
with three additional fields used by the local MCP layer:

* ``circuit_breaker_recovery_max`` -- upper bound for the exponential-backoff
  recovery wait. The base wait (``circuit_breaker_recovery``) doubles each
  consecutive open->half_open->open cycle, capped at this value.
* ``verify_ssl`` -- TLS certificate verification for HTTP/SSE transports.
  Defaults to ``True``; setting to ``False`` logs a WARNING.
* ``max_response_bytes`` -- per-response byte cap to protect against OOM
  from SIEM-scale payloads. Oversize responses are truncated and flagged.

The fields live in this local subclass (rather than the shared schema) so the
hardening can ship without changing the cross-package type contract.

Defaults can also be supplied via environment variables:

    BTAGENT_MCP_VERIFY_SSL                (default ``true``)
    BTAGENT_MCP_MAX_RESPONSE_BYTES        (default ``10485760`` -- 10 MiB)
    BTAGENT_MCP_CIRCUIT_RECOVERY_TIMEOUT_MAX (default ``600``)
"""

from __future__ import annotations

import os
from typing import Any

from btagent_shared.types.mcp import MCPServerConfig

DEFAULT_MAX_RESPONSE_BYTES = int(
    os.getenv("BTAGENT_MCP_MAX_RESPONSE_BYTES", str(10 * 1024 * 1024))
)
DEFAULT_VERIFY_SSL = os.getenv("BTAGENT_MCP_VERIFY_SSL", "true").lower() != "false"
DEFAULT_RECOVERY_TIMEOUT_MAX = float(
    os.getenv("BTAGENT_MCP_CIRCUIT_RECOVERY_TIMEOUT_MAX", "600")
)


class MCPHardenedServerConfig(MCPServerConfig):
    """Local extension adding hardening knobs to :class:`MCPServerConfig`.

    Backwards compatible: existing configs that don't specify these fields
    receive the secure-by-default values.
    """

    verify_ssl: bool = DEFAULT_VERIFY_SSL
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    circuit_breaker_recovery_max: int = int(DEFAULT_RECOVERY_TIMEOUT_MAX)


def get_verify_ssl(config: Any) -> bool:
    """Read ``verify_ssl`` from any config object, defaulting to True."""
    value = getattr(config, "verify_ssl", DEFAULT_VERIFY_SSL)
    return bool(value)


def get_max_response_bytes(config: Any) -> int:
    """Read ``max_response_bytes`` from any config object, defaulting to 10 MiB."""
    value = getattr(config, "max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
    return int(value)


def get_recovery_timeout_max(config: Any) -> float:
    """Read ``circuit_breaker_recovery_max`` from any config object."""
    value = getattr(config, "circuit_breaker_recovery_max", DEFAULT_RECOVERY_TIMEOUT_MAX)
    return float(value)
