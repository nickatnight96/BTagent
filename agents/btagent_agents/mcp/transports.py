"""MCP transport layer stubs.

Three transport types for connecting to MCP servers:
- StdioTransport  -- local MCP servers via subprocess stdin/stdout
- HTTPTransport   -- remote MCP servers via streamable-HTTP
- SSETransport    -- remote MCP servers via Server-Sent Events

Each implements a uniform connect / disconnect / send / receive interface.

Security notes
~~~~~~~~~~~~~~
HTTP-based transports verify TLS by default. ``verify_ssl=False`` is honoured
only when explicitly requested via configuration and is logged at WARNING.

All transports enforce a per-response byte cap (``max_response_bytes``,
default 10 MiB) to protect callers from OOM caused by SIEM-scale payloads.
When a response exceeds the cap it is truncated and the returned envelope
is flagged with ``"_truncated": True`` plus diagnostic metadata so downstream
nodes can react appropriately.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("btagent.mcp.transports")

# Default 10 MiB response cap. Mirrors ``MCPServerConfig.max_response_bytes``.
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


def _truncated_envelope(
    *,
    transport: str,
    raw: bytes,
    limit: int,
    parse_error: str | None = None,
) -> dict[str, Any]:
    """Build a flagged envelope when a response exceeds ``limit`` bytes.

    The envelope is intentionally minimal so that downstream agents can
    detect truncation via ``result.get("_truncated")`` without parsing
    transport-specific fields.
    """
    preview = raw[:limit].decode("utf-8", errors="replace")
    envelope: dict[str, Any] = {
        "_truncated": True,
        "_truncated_reason": "max_response_bytes_exceeded",
        "_truncated_transport": transport,
        "_truncated_size_bytes": len(raw),
        "_truncated_limit_bytes": limit,
        "_truncated_preview": preview,
    }
    if parse_error is not None:
        envelope["_truncated_parse_error"] = parse_error
    logger.warning(
        "%s response truncated: %d bytes exceeds cap of %d bytes",
        transport,
        len(raw),
        limit,
    )
    return envelope


# ---------------------------------------------------------------------------
# Base transport
# ---------------------------------------------------------------------------
class MCPTransportBase(ABC):
    """Abstract base for MCP transports."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish the transport connection."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Tear down the transport connection."""

    @abstractmethod
    async def send(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message to the MCP server."""

    @abstractmethod
    async def receive(self) -> dict[str, Any]:
        """Receive the next JSON-RPC response from the MCP server."""

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Whether the transport is currently connected."""


# ---------------------------------------------------------------------------
# Stdio transport -- subprocess
# ---------------------------------------------------------------------------
@dataclass
class StdioTransport(MCPTransportBase):
    """Communicates with a local MCP server over subprocess stdin/stdout.

    The *command* is a list of strings, e.g.
    ``["python", "-m", "btagent_agents.mcp.servers.splunk_mcp"]``.
    """

    command: list[str]
    env: dict[str, str] = field(default_factory=dict)
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    _process: asyncio.subprocess.Process | None = field(  # type: ignore[type-arg]
        default=None, init=False, repr=False
    )
    _connected: bool = field(default=False, init=False)

    async def connect(self) -> None:
        if self._connected:
            return
        self._process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env or None,
        )
        self._connected = True
        logger.info(
            "StdioTransport connected: %s (pid=%s)",
            self.command,
            self._process.pid,
        )

    async def disconnect(self) -> None:
        if self._process is not None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (TimeoutError, ProcessLookupError):
                self._process.kill()
            self._process = None
        self._connected = False
        logger.info("StdioTransport disconnected: %s", self.command)

    async def send(self, message: dict[str, Any]) -> None:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("StdioTransport not connected")
        payload = json.dumps(message) + "\n"
        self._process.stdin.write(payload.encode())
        await self._process.stdin.drain()

    async def receive(self) -> dict[str, Any]:
        if self._process is None or self._process.stdout is None:
            raise RuntimeError("StdioTransport not connected")
        # ``readline`` is bounded by ``max_response_bytes + 1`` so a malicious
        # subprocess cannot starve us with an unbounded line.
        try:
            line = await self._process.stdout.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            line = exc.partial
        except asyncio.LimitOverrunError:
            # Buffer overflow -- drain whatever is available, truncate, flag.
            line = await self._process.stdout.read(self.max_response_bytes + 1)

        if not line:
            raise ConnectionError("StdioTransport: subprocess closed stdout")

        if len(line) > self.max_response_bytes:
            return _truncated_envelope(transport="stdio", raw=line, limit=self.max_response_bytes)
        try:
            return json.loads(line.decode())
        except json.JSONDecodeError as exc:
            # Honour the cap even for malformed payloads.
            return _truncated_envelope(
                transport="stdio",
                raw=line,
                limit=self.max_response_bytes,
                parse_error=str(exc),
            )

    @property
    def is_connected(self) -> bool:
        return self._connected and self._process is not None


# ---------------------------------------------------------------------------
# HTTP transport -- streamable-http
# ---------------------------------------------------------------------------
@dataclass
class HTTPTransport(MCPTransportBase):
    """Communicates with a remote MCP server over streamable HTTP.

    Uses HTTP POST for requests and streaming responses.
    """

    server_url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    verify_ssl: bool = True
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    _connected: bool = field(default=False, init=False)
    _session: Any = field(default=None, init=False, repr=False)  # aiohttp.ClientSession
    _connector: Any = field(default=None, init=False, repr=False)

    async def connect(self) -> None:
        if self._connected:
            return
        if not self.verify_ssl:
            logger.warning(
                "HTTPTransport TLS verification DISABLED for %s -- "
                "this should only be used for trusted local development",
                self.server_url,
            )
        try:
            import aiohttp

            self._connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self._session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                connector=self._connector,
            )
        except ImportError:
            # aiohttp is optional; mark connected for mock usage
            self._session = None
            self._connector = None
        self._connected = True
        logger.info(
            "HTTPTransport connected: %s (verify_ssl=%s)",
            self.server_url,
            self.verify_ssl,
        )

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        self._connector = None
        self._connected = False
        logger.info("HTTPTransport disconnected: %s", self.server_url)

    async def send(self, message: dict[str, Any]) -> None:
        if not self._connected:
            raise RuntimeError("HTTPTransport not connected")
        if self._session is None:
            raise RuntimeError("HTTPTransport: aiohttp not installed")
        url = f"{self.server_url.rstrip('/')}/mcp"
        async with self._session.post(url, json=message) as resp:
            resp.raise_for_status()

    async def receive(self) -> dict[str, Any]:
        if not self._connected:
            raise RuntimeError("HTTPTransport not connected")
        if self._session is None:
            raise RuntimeError("HTTPTransport: aiohttp not installed")
        url = f"{self.server_url.rstrip('/')}/mcp"
        async with self._session.get(url) as resp:
            resp.raise_for_status()
            return await _read_capped_json(resp, transport="http", limit=self.max_response_bytes)

    @property
    def is_connected(self) -> bool:
        return self._connected


# ---------------------------------------------------------------------------
# SSE transport -- Server-Sent Events
# ---------------------------------------------------------------------------
@dataclass
class SSETransport(MCPTransportBase):
    """Communicates with a remote MCP server via Server-Sent Events.

    POST requests for commands, SSE stream for responses.
    """

    server_url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    verify_ssl: bool = True
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    _connected: bool = field(default=False, init=False)
    _session: Any = field(default=None, init=False, repr=False)
    _connector: Any = field(default=None, init=False, repr=False)
    _event_queue: asyncio.Queue[dict[str, Any]] = field(
        default_factory=asyncio.Queue, init=False, repr=False
    )

    async def connect(self) -> None:
        if self._connected:
            return
        if not self.verify_ssl:
            logger.warning(
                "SSETransport TLS verification DISABLED for %s -- "
                "this should only be used for trusted local development",
                self.server_url,
            )
        try:
            import aiohttp

            self._connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self._session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                connector=self._connector,
            )
        except ImportError:
            self._session = None
            self._connector = None
        self._connected = True
        logger.info(
            "SSETransport connected: %s (verify_ssl=%s)",
            self.server_url,
            self.verify_ssl,
        )

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        self._connector = None
        self._connected = False
        logger.info("SSETransport disconnected: %s", self.server_url)

    async def send(self, message: dict[str, Any]) -> None:
        if not self._connected:
            raise RuntimeError("SSETransport not connected")
        if self._session is None:
            raise RuntimeError("SSETransport: aiohttp not installed")
        url = f"{self.server_url.rstrip('/')}/mcp"
        async with self._session.post(url, json=message) as resp:
            resp.raise_for_status()

    async def receive(self) -> dict[str, Any]:
        """Receive next SSE event as parsed JSON.

        In a full implementation this reads from an SSE event stream.
        Currently returns from an internal queue for stub usage. The
        cap is enforced at enqueue time by callers using :func:`enforce_cap`.
        """
        if not self._connected:
            raise RuntimeError("SSETransport not connected")
        return await self._event_queue.get()

    @property
    def is_connected(self) -> bool:
        return self._connected


# ---------------------------------------------------------------------------
# Helpers -- streaming read with cap enforcement
# ---------------------------------------------------------------------------
async def _read_capped_json(resp: Any, *, transport: str, limit: int) -> dict[str, Any]:
    """Read an aiohttp response in bounded chunks and parse as JSON.

    Returns a truncation envelope (rather than parsed JSON) when the body
    exceeds *limit* bytes. The connection is drained up to ``limit + 1``
    so the caller still gets a deterministic outcome rather than hanging
    on an unbounded body.
    """
    chunks: list[bytes] = []
    total = 0
    # ``content.iter_chunked`` is the streaming primitive in aiohttp; we
    # bail out as soon as we cross the limit + 1 mark.
    try:
        async for chunk in resp.content.iter_chunked(64 * 1024):
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                break
    except AttributeError:
        # Mock responses without ``iter_chunked`` -- fall back to ``read``.
        body = await resp.read()
        total = len(body)
        chunks = [body]

    raw = b"".join(chunks)
    if total > limit:
        return _truncated_envelope(transport=transport, raw=raw, limit=limit)

    try:
        return json.loads(raw.decode())
    except json.JSONDecodeError as exc:
        return _truncated_envelope(
            transport=transport,
            raw=raw,
            limit=limit,
            parse_error=str(exc),
        )


def build_transport(config: Any) -> MCPTransportBase:
    """Construct a transport instance from an :class:`MCPServerConfig`.

    Centralises the plumbing of ``verify_ssl`` and ``max_response_bytes``
    from the config object into the transport so individual server
    impls don't need to know about the new fields. Backwards-compat:
    fields are read via the helpers in :mod:`btagent_agents.mcp.config`
    which fall back to safe defaults when the field is absent (as it is
    on the legacy :class:`btagent_shared.types.mcp.MCPServerConfig`).
    """
    from btagent_shared.types.config import MCPTransport

    from btagent_agents.mcp.config import get_max_response_bytes, get_verify_ssl

    verify_ssl = get_verify_ssl(config)
    max_bytes = get_max_response_bytes(config)
    timeout = int(getattr(config, "timeout_seconds", 30))
    transport_kind = getattr(config, "transport", MCPTransport.STDIO)

    if transport_kind == MCPTransport.STDIO:
        command = list(getattr(config, "command", None) or [])
        return StdioTransport(
            command=command,
            max_response_bytes=max_bytes,
        )
    if transport_kind == MCPTransport.STREAMABLE_HTTP:
        return HTTPTransport(
            server_url=getattr(config, "server_url", "") or "",
            timeout_seconds=timeout,
            verify_ssl=verify_ssl,
            max_response_bytes=max_bytes,
        )
    if transport_kind == MCPTransport.SSE:
        return SSETransport(
            server_url=getattr(config, "server_url", "") or "",
            timeout_seconds=timeout,
            verify_ssl=verify_ssl,
            max_response_bytes=max_bytes,
        )
    raise ValueError(f"Unknown MCP transport: {transport_kind!r}")


def enforce_cap(
    payload: bytes | str | dict[str, Any],
    *,
    limit: int = DEFAULT_MAX_RESPONSE_BYTES,
    transport: str = "generic",
) -> dict[str, Any]:
    """Validate an arbitrary payload against the response cap.

    Useful for callers that buffer the body themselves (e.g. an SSE
    event before enqueuing it). Returns either the parsed dict or a
    truncation envelope.
    """
    if isinstance(payload, dict):
        encoded = json.dumps(payload).encode()
    elif isinstance(payload, str):
        encoded = payload.encode()
    else:
        encoded = payload

    if len(encoded) > limit:
        return _truncated_envelope(transport=transport, raw=encoded, limit=limit)
    if isinstance(payload, dict):
        return payload
    try:
        return json.loads(encoded.decode())
    except json.JSONDecodeError as exc:
        return _truncated_envelope(
            transport=transport, raw=encoded, limit=limit, parse_error=str(exc)
        )
