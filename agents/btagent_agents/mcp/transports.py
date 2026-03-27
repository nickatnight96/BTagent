"""MCP transport layer stubs.

Three transport types for connecting to MCP servers:
- StdioTransport  -- local MCP servers via subprocess stdin/stdout
- HTTPTransport   -- remote MCP servers via streamable-HTTP
- SSETransport    -- remote MCP servers via Server-Sent Events

Each implements a uniform connect / disconnect / send / receive interface.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("btagent.mcp.transports")


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

    _process: asyncio.subprocess.Process | None = field(  # type: ignore[type-arg]
        default=None, init=False, repr=False
    )
    _connected: bool = field(default=False, init=False)
    _read_buffer: str = field(default="", init=False, repr=False)

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
        logger.info("StdioTransport connected: %s (pid=%s)", self.command, self._process.pid)

    async def disconnect(self) -> None:
        if self._process is not None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (asyncio.TimeoutError, ProcessLookupError):
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
        line = await self._process.stdout.readline()
        if not line:
            raise ConnectionError("StdioTransport: subprocess closed stdout")
        return json.loads(line.decode())

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

    _connected: bool = field(default=False, init=False)
    _session: Any = field(default=None, init=False, repr=False)  # aiohttp.ClientSession

    async def connect(self) -> None:
        if self._connected:
            return
        try:
            import aiohttp

            self._session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
            )
        except ImportError:
            # Graceful fallback -- aiohttp is optional.  The transport is
            # marked as connected for mock usage even without it.
            self._session = None
        self._connected = True
        logger.info("HTTPTransport connected: %s", self.server_url)

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        self._connected = False
        logger.info("HTTPTransport disconnected: %s", self.server_url)

    async def send(self, message: dict[str, Any]) -> None:
        if not self._connected:
            raise RuntimeError("HTTPTransport not connected")
        if self._session is None:
            raise RuntimeError(
                "HTTPTransport: aiohttp not installed -- cannot send over HTTP"
            )
        url = f"{self.server_url.rstrip('/')}/mcp"
        async with self._session.post(url, json=message) as resp:
            resp.raise_for_status()

    async def receive(self) -> dict[str, Any]:
        if not self._connected:
            raise RuntimeError("HTTPTransport not connected")
        if self._session is None:
            raise RuntimeError(
                "HTTPTransport: aiohttp not installed -- cannot receive over HTTP"
            )
        url = f"{self.server_url.rstrip('/')}/mcp"
        async with self._session.get(url) as resp:
            resp.raise_for_status()
            return await resp.json()

    @property
    def is_connected(self) -> bool:
        return self._connected


# ---------------------------------------------------------------------------
# SSE transport -- Server-Sent Events
# ---------------------------------------------------------------------------
@dataclass
class SSETransport(MCPTransportBase):
    """Communicates with a remote MCP server via Server-Sent Events.

    POST requests for commands, SSE stream for responses / notifications.
    """

    server_url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30

    _connected: bool = field(default=False, init=False)
    _session: Any = field(default=None, init=False, repr=False)
    _event_queue: asyncio.Queue[dict[str, Any]] = field(
        default_factory=asyncio.Queue, init=False, repr=False
    )

    async def connect(self) -> None:
        if self._connected:
            return
        try:
            import aiohttp

            self._session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
            )
        except ImportError:
            self._session = None
        self._connected = True
        logger.info("SSETransport connected: %s", self.server_url)

    async def disconnect(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        self._connected = False
        logger.info("SSETransport disconnected: %s", self.server_url)

    async def send(self, message: dict[str, Any]) -> None:
        if not self._connected:
            raise RuntimeError("SSETransport not connected")
        if self._session is None:
            raise RuntimeError(
                "SSETransport: aiohttp not installed -- cannot send via SSE"
            )
        url = f"{self.server_url.rstrip('/')}/mcp"
        async with self._session.post(url, json=message) as resp:
            resp.raise_for_status()

    async def receive(self) -> dict[str, Any]:
        """Receive next SSE event as parsed JSON.

        In a full implementation this would read from an SSE event stream.
        Currently returns from an internal queue for stub usage.
        """
        if not self._connected:
            raise RuntimeError("SSETransport not connected")
        return await self._event_queue.get()

    @property
    def is_connected(self) -> bool:
        return self._connected
