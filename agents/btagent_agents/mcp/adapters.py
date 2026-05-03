"""Resilient MCP tool execution adapters.

Provides wrappers around MCP tool calls with:
- Retry logic with exponential backoff (``ResilientMCPToolAdapter``)
- Large-result file offloading (``FileWritingAdapter``)
- Circuit breaker integration for fail-fast behaviour
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from btagent_shared.security import TLPViolation, assert_tlp_allows_egress
from btagent_shared.types.config import TLP

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    MCPConnectionRegistry,
)

logger = logging.getLogger("btagent.mcp.adapters")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 1.0  # seconds
DEFAULT_BACKOFF_MAX = 30.0  # cap
LARGE_RESULT_THRESHOLD = 10 * 1024  # 10 KB
ARTIFACT_DIR = os.getenv(
    "BTAGENT_ARTIFACT_DIR",
    os.path.join(os.getcwd(), ".btagent_artifacts"),
)


# ---------------------------------------------------------------------------
# ResilientMCPToolAdapter
# ---------------------------------------------------------------------------
@dataclass
class ResilientMCPToolAdapter:
    """Wraps MCP tool calls with retry, backoff, and circuit breaker.

    Usage::

        adapter = ResilientMCPToolAdapter(server_name="splunk")
        result = await adapter.execute(
            tool_name="splunk_search",
            arguments={"query": "index=network ..."},
        )
    """

    server_name: str
    max_retries: int = DEFAULT_MAX_RETRIES
    backoff_base: float = DEFAULT_BACKOFF_BASE
    backoff_max: float = DEFAULT_BACKOFF_MAX
    investigation_tlp: str | None = None
    registry: MCPConnectionRegistry | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.registry is None:
            self.registry = MCPConnectionRegistry.get_instance()

    # ----- circuit breaker check -----

    def _check_circuit(self) -> None:
        """Raise if the circuit breaker for this server is open."""
        conn = self.registry._connections.get(self.server_name)  # type: ignore[union-attr]
        if conn is not None:
            conn.circuit_breaker.check_state()

    def _record_success(self) -> None:
        self.registry.record_success(self.server_name)  # type: ignore[union-attr]

    def _record_failure(self, error: Exception) -> None:
        self.registry.record_failure(self.server_name, error)  # type: ignore[union-attr]

    # ----- execute with retry -----

    async def execute(
        self,
        tool_fn: Any,
        *,
        tool_name: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute *tool_fn* with retry + exponential backoff.

        Args:
            tool_fn: Async callable to invoke (the MCP tool coroutine).
            tool_name: For logging / error messages.
            arguments: Keyword arguments forwarded to *tool_fn*.

        Returns:
            The tool result dict.

        Raises:
            CircuitOpenError: If the circuit breaker is open and all
                retries are exhausted or the circuit never recovers.
            Exception: The last exception if all retries fail.
        """
        arguments = arguments or {}
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                self._check_circuit()
            except CircuitOpenError:
                if attempt == self.max_retries:
                    raise
                delay = self._backoff_delay(attempt)
                logger.warning(
                    "Circuit open for %s, waiting %.1fs before retry %d/%d",
                    self.server_name,
                    delay,
                    attempt,
                    self.max_retries,
                )
                await asyncio.sleep(delay)
                continue

            try:
                result = await tool_fn(**arguments)
                self._record_success()
                return _enforce_tlp_on_mcp_return(
                    result,
                    server_name=self.server_name,
                    tool_name=tool_name,
                    investigation_tlp=self.investigation_tlp,
                )

            except CircuitOpenError:
                raise

            except Exception as exc:
                last_error = exc
                self._record_failure(exc)
                logger.warning(
                    "MCP tool %s/%s attempt %d/%d failed: %s",
                    self.server_name,
                    tool_name,
                    attempt,
                    self.max_retries,
                    exc,
                )
                if attempt < self.max_retries:
                    delay = self._backoff_delay(attempt)
                    await asyncio.sleep(delay)

        # All retries exhausted
        if last_error is not None:
            raise last_error
        raise RuntimeError(f"MCP tool {tool_name} failed after {self.max_retries} retries")

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff: base * 2^(attempt-1) capped at backoff_max."""
        return min(self.backoff_base * (2 ** (attempt - 1)), self.backoff_max)


# ---------------------------------------------------------------------------
# TLP egress filter for MCP returns
# ---------------------------------------------------------------------------
def _is_red_tagged(node: Any) -> bool:
    """Return True if a dict node is itself tagged TLP:RED."""
    if not isinstance(node, dict):
        return False
    for key in ("tlp_level", "tlp", "TLP", "TLPLevel"):
        val = node.get(key)
        if isinstance(val, str) and val.lower() == "red":
            return True
    return False


def _strip_red_items(node: Any) -> tuple[Any, int]:
    """Recursively remove any RED-tagged dict from *node*.

    Returns the cleaned structure plus the number of items stripped. RED
    entries inside lists are dropped; nested dict values that are RED are
    replaced with a placeholder reference. The MCP envelope itself is never
    silently swallowed -- the caller raises if the *whole* envelope is RED.
    """
    stripped = 0
    if isinstance(node, dict):
        cleaned: dict[str, Any] = {}
        for key, value in node.items():
            if _is_red_tagged(value):
                stripped += 1
                cleaned[key] = {
                    "_tlp_redacted": True,
                    "reason": "TLP:RED data not propagated outside investigation",
                }
                continue
            new_value, sub = _strip_red_items(value)
            stripped += sub
            cleaned[key] = new_value
        return cleaned, stripped
    if isinstance(node, list):
        cleaned_list: list[Any] = []
        for item in node:
            if _is_red_tagged(item):
                stripped += 1
                continue
            new_item, sub = _strip_red_items(item)
            stripped += sub
            cleaned_list.append(new_item)
        return cleaned_list, stripped
    return node, 0


def _enforce_tlp_on_mcp_return(
    result: dict[str, Any],
    *,
    server_name: str,
    tool_name: str,
    investigation_tlp: str | None,
) -> dict[str, Any]:
    """Apply the TLP egress gate to a returning MCP envelope.

    1. If the envelope itself is RED-tagged, raise :class:`TLPViolation` --
       the entire payload is restricted and we will not propagate it into
       agent state.
    2. Otherwise strip RED-tagged children and call
       :func:`assert_tlp_allows_egress` to confirm nothing RED slipped past.
    """
    if _is_red_tagged(result):
        logger.error(
            "Refusing to return TLP:RED MCP envelope from %s/%s",
            server_name,
            tool_name,
        )
        raise TLPViolation(TLP.RED, f"mcp:{server_name}")

    cleaned, stripped = _strip_red_items(result)
    if stripped:
        logger.warning(
            "Stripped %d TLP:RED-tagged item(s) from MCP return %s/%s",
            stripped,
            server_name,
            tool_name,
        )
        if isinstance(cleaned, dict):
            cleaned.setdefault("_tlp_stripped_count", stripped)

    # Defensive: ensure no RED tag remains.
    assert_tlp_allows_egress(
        cleaned,
        "mcp_return",
        classification_ctx=investigation_tlp,
    )
    return cleaned  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# FileWritingAdapter
# ---------------------------------------------------------------------------
@dataclass
class FileWritingAdapter:
    """Offloads large tool results to artifact files.

    When a tool result exceeds ``threshold`` bytes (default 10 KB), the
    full result is written to a file and replaced with a reference dict.

    Usage::

        adapter = FileWritingAdapter()
        result = adapter.maybe_offload(result, tool_name="splunk_search")
    """

    threshold: int = LARGE_RESULT_THRESHOLD
    artifact_dir: str = ARTIFACT_DIR

    def __post_init__(self) -> None:
        Path(self.artifact_dir).mkdir(parents=True, exist_ok=True)

    def maybe_offload(
        self,
        result: dict[str, Any],
        *,
        tool_name: str = "unknown",
        investigation_id: str = "",
    ) -> dict[str, Any]:
        """If *result* is large, write to file and return a reference.

        Args:
            result: The tool result dict.
            tool_name: For filename generation.
            investigation_id: Optional investigation context.

        Returns:
            Either the original result (if small) or a reference dict
            pointing to the artifact file.
        """
        serialised = json.dumps(result, default=str)
        size = len(serialised.encode("utf-8"))

        if size <= self.threshold:
            return result

        # Generate deterministic filename
        ts = int(time.time())
        content_hash = hashlib.sha256(serialised.encode()).hexdigest()[:12]
        prefix = investigation_id or "global"
        filename = f"{prefix}_{tool_name}_{ts}_{content_hash}.json"
        filepath = os.path.join(self.artifact_dir, filename)

        # Write
        with open(filepath, "w") as f:
            f.write(serialised)

        logger.info(
            "Offloaded large result from %s (%d bytes) to %s",
            tool_name,
            size,
            filepath,
        )

        # Return reference
        return {
            "status": result.get("status", "success"),
            "offloaded": True,
            "artifact_path": filepath,
            "artifact_size_bytes": size,
            "tool_name": tool_name,
            "summary": self._summarise(result),
        }

    @staticmethod
    def _summarise(result: dict[str, Any]) -> str:
        """Generate a brief summary of an offloaded result."""
        parts: list[str] = []

        # Count common list fields
        for key in ("events", "hits", "alerts", "detections", "incidents", "notables", "rows"):
            if key in result and isinstance(result[key], list):
                parts.append(f"{len(result[key])} {key}")

        if "total" in result:
            parts.append(f"total={result['total']}")

        if "result_count" in result:
            parts.append(f"results={result['result_count']}")

        if parts:
            return f"Large result offloaded to file ({', '.join(parts)})"
        return "Large result offloaded to file"


# ---------------------------------------------------------------------------
# Convenience: combined resilient + file-writing adapter
# ---------------------------------------------------------------------------
@dataclass
class MCPToolExecutor:
    """Combined adapter: resilient retry + file offloading.

    This is the recommended adapter for production tool execution::

        executor = MCPToolExecutor(server_name="splunk")
        result = await executor.invoke(
            tool_fn=splunk_server.splunk_search,
            tool_name="splunk_search",
            arguments={"query": "index=network ..."},
        )
    """

    server_name: str
    max_retries: int = DEFAULT_MAX_RETRIES
    offload_threshold: int = LARGE_RESULT_THRESHOLD
    investigation_id: str = ""
    investigation_tlp: str | None = None

    _resilient: ResilientMCPToolAdapter = field(init=False, repr=False)
    _file_adapter: FileWritingAdapter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._resilient = ResilientMCPToolAdapter(
            server_name=self.server_name,
            max_retries=self.max_retries,
            investigation_tlp=self.investigation_tlp,
        )
        self._file_adapter = FileWritingAdapter(threshold=self.offload_threshold)

    async def invoke(
        self,
        tool_fn: Any,
        *,
        tool_name: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool with retry + optional file offloading."""
        result = await self._resilient.execute(
            tool_fn,
            tool_name=tool_name,
            arguments=arguments,
        )
        return self._file_adapter.maybe_offload(
            result,
            tool_name=tool_name,
            investigation_id=self.investigation_id,
        )
