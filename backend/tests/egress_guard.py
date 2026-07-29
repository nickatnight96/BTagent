"""Zero-egress guard used by ``test_zero_egress.py`` (Sovereign Pack, #502).

The Sovereign Pack ships a *claim*: in the default posture
(``BTAGENT_MOCK_CONNECTORS=true`` plus a local/mock LLM and a local embedding
provider) BTagent makes **no outbound network calls**. A claim in a README
rots the first time somebody adds an unguarded ``httpx.get``. This module is
the instrumentation that makes the claim executable.

What it does
------------
:class:`EgressGuard` is a context manager that wraps every outbound network
primitive the codebase can reach and refuses any destination that is not
loopback:

* ``socket.socket.connect`` / ``connect_ex`` / ``socket.create_connection`` —
  the floor under *every* Python network client, including ones nobody
  remembered to instrument;
* ``socket.getaddrinfo`` — a DNS lookup for an external name is itself egress
  (it leaks the name to a resolver), and catching it here means an external
  host is refused even when it would not have resolved at all;
* ``httpx.Client.send`` / ``httpx.AsyncClient.send`` — the HTTP layer the
  backend, the embedding service and the CTI integrations use;
* ``aiohttp.ClientSession._request`` — the MCP HTTP/SSE transports;
* ``urllib.request.urlopen`` — stdlib fallback.

Loopback (``127.0.0.0/8``, ``::1``, ``localhost``) and AF_UNIX are *allowed
but recorded*: an air-gapped deployment legitimately talks to a local
PostgreSQL, Redis, MinIO and Ollama. Everything else raises
:class:`EgressViolation` at the call site, so the failing test points straight
at the offending line rather than at a summary assertion.

In-process ASGI transports (``httpx.ASGITransport``, ``MockTransport``,
``WSGITransport``) are allowed unconditionally — they never touch a socket;
that is how the FastAPI test client drives the app.

What it deliberately does NOT prove
-----------------------------------
* It only observes the Python process. A sidecar, a base-image entrypoint or
  a native extension opening its own socket is invisible to it.
* It observes the code paths the exercising test actually walks. Unwalked code
  is unproven — the accompanying test enumerates what it covers.
* Live-connector code paths are out of scope by construction: they raise
  ``NotImplementedError`` before any client is built, and turning them on is
  precisely the operator decision the air-gap docs tell you not to make.

The suite's own canary tests assert the guard *fires* on a deliberate external
call, so a future refactor that neuters the patching turns the suite red
instead of silently passing.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from dataclasses import dataclass
from types import TracebackType
from typing import Any

__all__ = [
    "EgressAttempt",
    "EgressGuard",
    "EgressViolation",
    "is_loopback_host",
]


class EgressViolation(AssertionError):
    """Raised the moment a non-loopback destination is contacted.

    Subclasses ``AssertionError`` so an escaped violation reads as a test
    failure rather than an infrastructure error, and so a well-meaning
    ``except Exception`` in product code is less likely to swallow it
    silently... though see :meth:`EgressGuard.assert_no_egress`, which
    re-raises from the recorded ledger precisely because product code *does*
    contain broad handlers (``MemoryService._embed`` swallows everything by
    design).
    """


@dataclass(frozen=True)
class EgressAttempt:
    """One observed outbound attempt."""

    layer: str
    target: str

    def __str__(self) -> str:  # pragma: no cover - formatting only
        return f"{self.layer} -> {self.target}"


_LOOPBACK_NAMES = frozenset(
    {
        "",
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        # httpx's ASGI test client base_url host. It never leaves the process,
        # but a belt-and-braces entry keeps a stray raw-socket path honest.
        "testserver",
    }
)


def is_loopback_host(host: str | None) -> bool:
    """True when *host* can only ever resolve to this machine.

    Hostnames are treated as loopback only when they are on the explicit
    allowlist — ``example.local`` is *not* assumed local, because assuming it
    is would be the exact silent hole this module exists to close.
    """
    if host is None:
        return True
    name = str(host).strip().strip("[]").lower()
    if name in _LOOPBACK_NAMES or name.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(name)
    except ValueError:
        return False
    # ``0.0.0.0`` / ``::`` are "unspecified" — a bind target, never a route off
    # the box.
    return bool(addr.is_loopback or addr.is_unspecified)


def _host_from_address(address: Any) -> str:
    """Best-effort host extraction from a ``socket`` address tuple."""
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address)


class EgressGuard:
    """Context manager that refuses (and records) non-loopback egress.

    Usage::

        with EgressGuard() as guard:
            ...  # exercise the app
        guard.assert_no_egress()
    """

    def __init__(self) -> None:
        self.allowed: list[EgressAttempt] = []
        self.violations: list[EgressAttempt] = []
        self._undo: list[tuple[Any, str, Any]] = []
        self._active = False

    # -- recording ---------------------------------------------------------

    def _check(self, layer: str, host: str | None, target: str | None = None) -> None:
        attempt = EgressAttempt(layer=layer, target=target or str(host))
        if is_loopback_host(host):
            self.allowed.append(attempt)
            return
        self.violations.append(attempt)
        raise EgressViolation(
            f"Outbound network call blocked by the zero-egress guard: {attempt}. "
            "The default posture (BTAGENT_MOCK_CONNECTORS=true + local/mock LLM "
            "and embeddings) must not reach anything off-box."
        )

    def assert_no_egress(self) -> None:
        """Fail if anything non-loopback was attempted inside the block.

        Necessary in addition to the raise-at-call-site behaviour because some
        product code catches broad exceptions on purpose (memory embedding is
        best-effort and swallows failures), which would otherwise convert a
        violation into a silent degradation.
        """
        if self.violations:
            rendered = "\n  ".join(str(v) for v in self.violations)
            raise EgressViolation(
                f"{len(self.violations)} outbound network attempt(s) escaped the "
                f"default posture:\n  {rendered}"
            )

    # -- patching ----------------------------------------------------------

    def _patch(self, obj: Any, name: str, replacement: Any) -> None:
        original = getattr(obj, name)
        self._undo.append((obj, name, original))
        setattr(obj, name, replacement)

    def _install(self) -> None:
        guard = self

        # --- raw sockets ---------------------------------------------------
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_create_connection = socket.create_connection
        real_getaddrinfo = socket.getaddrinfo

        def _socket_layer(sock: Any) -> str | None:
            """Return the address host for AF_INET/AF_INET6, else None (allow)."""
            family = getattr(sock, "family", None)
            if family in (socket.AF_INET, socket.AF_INET6):
                return "inet"
            return None

        def connect(self_sock: Any, address: Any) -> Any:  # noqa: ANN401
            if _socket_layer(self_sock) is not None:
                guard._check("socket.connect", _host_from_address(address), str(address))
            return real_connect(self_sock, address)

        def connect_ex(self_sock: Any, address: Any) -> Any:  # noqa: ANN401
            if _socket_layer(self_sock) is not None:
                guard._check("socket.connect_ex", _host_from_address(address), str(address))
            return real_connect_ex(self_sock, address)

        def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            guard._check("socket.create_connection", _host_from_address(address), str(address))
            return real_create_connection(address, *args, **kwargs)

        def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            guard._check("socket.getaddrinfo", host, f"{host}:{port}")
            return real_getaddrinfo(host, port, *args, **kwargs)

        self._patch(socket.socket, "connect", connect)
        self._patch(socket.socket, "connect_ex", connect_ex)
        self._patch(socket, "create_connection", create_connection)
        self._patch(socket, "getaddrinfo", getaddrinfo)

        # --- httpx ---------------------------------------------------------
        import httpx

        in_process_transports: tuple[type, ...] = tuple(
            t
            for t in (
                getattr(httpx, "ASGITransport", None),
                getattr(httpx, "WSGITransport", None),
                getattr(httpx, "MockTransport", None),
            )
            if isinstance(t, type)
        )

        def _httpx_check(client: Any, request: Any, layer: str) -> None:
            transport = getattr(client, "_transport", None)
            if in_process_transports and isinstance(transport, in_process_transports):
                # Never touches a socket — this is how the FastAPI test client
                # drives the ASGI app in-process.
                return
            guard._check(layer, request.url.host, str(request.url))

        real_sync_send = httpx.Client.send
        real_async_send = httpx.AsyncClient.send

        def sync_send(self_client: Any, request: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            _httpx_check(self_client, request, "httpx.Client.send")
            return real_sync_send(self_client, request, **kwargs)

        async def async_send(self_client: Any, request: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            _httpx_check(self_client, request, "httpx.AsyncClient.send")
            return await real_async_send(self_client, request, **kwargs)

        self._patch(httpx.Client, "send", sync_send)
        self._patch(httpx.AsyncClient, "send", async_send)

        # --- aiohttp (MCP HTTP / SSE transports) ---------------------------
        try:
            import aiohttp
        except ImportError:  # pragma: no cover - aiohttp is an agents-tier dep
            aiohttp = None  # type: ignore[assignment]

        if aiohttp is not None:
            real_request = aiohttp.ClientSession._request

            async def aiohttp_request(
                self_session: Any,  # noqa: ANN401
                method: str,
                str_or_url: Any,  # noqa: ANN401
                **kwargs: Any,
            ) -> Any:
                host = getattr(str_or_url, "host", None)
                if host is None:
                    from urllib.parse import urlsplit

                    host = urlsplit(str(str_or_url)).hostname
                guard._check("aiohttp.request", host, f"{method} {str_or_url}")
                return await real_request(self_session, method, str_or_url, **kwargs)

            self._patch(aiohttp.ClientSession, "_request", aiohttp_request)

        # --- urllib --------------------------------------------------------
        real_urlopen = urllib.request.urlopen

        def urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            from urllib.parse import urlsplit

            raw = getattr(url, "full_url", url)
            guard._check("urllib.urlopen", urlsplit(str(raw)).hostname, str(raw))
            return real_urlopen(url, *args, **kwargs)

        self._patch(urllib.request, "urlopen", urlopen)

    def _uninstall(self) -> None:
        for obj, name, original in reversed(self._undo):
            setattr(obj, name, original)
        self._undo.clear()

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> EgressGuard:
        if self._active:  # pragma: no cover - defensive
            raise RuntimeError("EgressGuard is not re-entrant")
        self._install()
        self._active = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        self._uninstall()
        self._active = False
        return False
