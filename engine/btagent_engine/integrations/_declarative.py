"""Generic HTTP runner for declaratively-authored connectors (#101).

Takes a :class:`~btagent_shared.types.connector_routing.RoutingSpec` (from
a capability in the connector manifest), the resolved credential, and the
tool inputs — and executes the call. No per-vendor Python.

What the runner owns, so connector authors don't have to:

* **Mock-first execution.** ``BTAGENT_MOCK_CONNECTORS`` (default *true*)
  swaps the HTTP sender for the connector's fixture sender. Everything
  else — request building, auth placement, retries, pagination, status
  mapping, response mapping — runs *identically* in both modes, so the
  mock path exercises the real spec rather than a parallel code path.
* **Live egress gating.** A spec must opt in via
  ``routing.live_egress_approved``. Until it does, turning mock mode off
  raises ``NotImplementedError`` — the same stance every programmatic
  connector in this package already takes.
* **Retries with exponential backoff** on 429/5xx/timeouts only.
* **Pagination** — cursor, page-number, and offset styles.
* **Error mapping** — any other non-2xx becomes a
  :class:`ConnectorHTTPError` carrying the status and a short, scrubbed
  body excerpt.
* **Secret hygiene.** The resolved credential is scrubbed out of every
  log line and every exception message this module produces — including
  the request URL, which carries the key for ``api_key_query`` auth.

What the runner deliberately does **not** own: policy. TLP-egress and
``hitl_required`` gating stay in
:class:`~btagent_engine.middleware.connector_policy.ConnectorPolicyMiddleware`,
which runs *before* ``Node.run`` and therefore before this runner is ever
reached. A declarative capability is gated exactly like a programmatic
one; there is no path from a workflow into this module that skips the
middleware chain.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
from base64 import b64encode
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from btagent_shared.types.connector import ConnectorManifest
from btagent_shared.types.connector_routing import (
    AuthStyle,
    PaginationStyle,
    ParamLocation,
    RequestParam,
    RoutingSpec,
    extract_path,
)
from btagent_shared.utils.secrets import resolve_secret

from btagent_engine.middleware._redaction import redact_secrets

logger = logging.getLogger("btagent.engine.integrations.declarative")

#: Placeholder credential used in mock mode when the real reference does
#: not resolve. Mock runs must never require a live secret.
MOCK_CREDENTIAL = "mock-credential-not-a-real-secret"


def mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConnectorError(RuntimeError):
    """Base class for declarative-connector failures."""


class ConnectorConfigError(ConnectorError):
    """The manifest / routing spec cannot produce a request (author bug)."""


class ConnectorAuthError(ConnectorError):
    """The declared credential reference did not resolve to usable material."""


class ConnectorTransportError(ConnectorError):
    """The request never produced an HTTP response (DNS, TLS, timeout)."""


class ConnectorHTTPError(ConnectorError):
    """A non-2xx response the spec does not classify as 'not found'."""

    def __init__(
        self,
        *,
        connector: str,
        capability: str,
        status_code: int,
        detail: str = "",
    ) -> None:
        message = f"{connector}.{capability}: HTTP {status_code}"
        if detail:
            message = f"{message} — {detail}"
        super().__init__(message)
        self.connector = connector
        self.capability = capability
        self.status_code = status_code
        self.detail = detail


# ---------------------------------------------------------------------------
# Transport value objects
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HTTPRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    json_body: dict[str, Any] | None = None
    timeout_seconds: float = 15.0


@dataclass(slots=True)
class HTTPResponse:
    status_code: int
    json_body: Any = None
    text: str = ""


#: A sender turns a request into a response. The live sender talks to the
#: network; a connector's mock sender answers from fixtures; tests inject
#: their own. Sync callables are accepted for fixture convenience.
Sender = Callable[[HTTPRequest], "HTTPResponse | Awaitable[HTTPResponse]"]


class _Scrubber:
    """Removes resolved credential material from anything we emit."""

    def __init__(self) -> None:
        self._values: list[str] = []

    def guard(self, value: str | None) -> None:
        if value and len(value) >= 4 and value not in self._values:
            self._values.append(value)

    def __call__(self, text: str) -> str:
        if not text:
            return text
        for secret in self._values:
            text = text.replace(secret, "[REDACTED:credential]")
        return redact_secrets(text)


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------

_BODY_EXCERPT_CHARS = 200


class DeclarativeConnector:
    """Executes the routing specs declared in a connector manifest.

    One instance per connector; ``execute`` is called with the capability
    id so a single connector can expose many declarative capabilities.
    """

    def __init__(
        self,
        manifest: ConnectorManifest,
        *,
        mock_sender: Sender | None = None,
        sender: Sender | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._manifest = manifest
        self._mock_sender = mock_sender
        self._sender = sender
        self._sleep = sleep or asyncio.sleep

    # -------------------------------------------------------------- #
    # Public API
    # -------------------------------------------------------------- #

    async def execute(self, capability_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
        """Run *capability_id* with *inputs* and return the mapped output."""
        spec = self.routing_for(capability_id)
        # Sender selection first: it carries the mock-first / live-egress
        # gate, and a call we are not allowed to make must not touch the
        # credential store at all.
        sender = self._select_sender(spec, capability_id)
        scrub = _Scrubber()
        credential = self._resolve_credential(spec, scrub)
        return await self._run(spec, capability_id, inputs, credential, sender, scrub)

    def routing_for(self, capability_id: str) -> RoutingSpec:
        """The routing spec for *capability_id*, or raise a config error."""
        capability = self._manifest.capability(capability_id)
        if capability is None:
            raise ConnectorConfigError(
                f"{self._manifest.name}: no capability {capability_id!r} in the manifest"
            )
        if capability.routing is None:
            raise ConnectorConfigError(
                f"{self._manifest.name}.{capability_id}: capability is not declarative "
                "(no routing block); it must be executed by its own Python implementation"
            )
        return capability.routing

    # -------------------------------------------------------------- #
    # Credentials
    # -------------------------------------------------------------- #

    def _resolve_credential(self, spec: RoutingSpec, scrub: _Scrubber) -> str | None:
        if spec.auth.style is AuthStyle.NONE:
            return None

        assert spec.auth.secret_ref is not None  # guaranteed by spec validation
        resolved = resolve_secret(spec.auth.secret_ref)
        usable = bool(resolved) and not resolved.startswith("<unresolved:")

        if not usable:
            if mock_mode_enabled():
                # Mock runs must never require live credential material.
                return MOCK_CREDENTIAL
            raise ConnectorAuthError(
                f"{self._manifest.name}: credential reference {spec.auth.secret_ref!r} "
                "did not resolve; wire it into Vault/AWS/env or run with "
                "BTAGENT_MOCK_CONNECTORS=true"
            )

        scrub.guard(resolved)
        return resolved

    # -------------------------------------------------------------- #
    # Sender selection — this is where mock-first is enforced
    # -------------------------------------------------------------- #

    def _select_sender(self, spec: RoutingSpec, capability_id: str) -> Sender:
        if self._sender is not None:
            # Explicit injection (tests, or a host supplying its own client).
            return self._sender
        if mock_mode_enabled():
            if self._mock_sender is None:
                raise ConnectorConfigError(
                    f"{self._manifest.name}.{capability_id}: BTAGENT_MOCK_CONNECTORS is on "
                    "but the connector registered no mock sender"
                )
            return self._mock_sender
        if not spec.live_egress_approved:
            raise NotImplementedError(
                f"{self._manifest.name}.{capability_id}: live egress is not approved for "
                "this declarative capability (routing.live_egress_approved=false); set "
                "BTAGENT_MOCK_CONNECTORS=true to use the mock fixtures."
            )
        return _httpx_sender

    # -------------------------------------------------------------- #
    # Request building
    # -------------------------------------------------------------- #

    def _param_value(self, param: RequestParam, inputs: dict[str, Any], capability_id: str) -> Any:
        if param.value is not None:
            return param.value
        assert param.source is not None  # guaranteed by spec validation
        value = inputs.get(param.source)
        if value is None:
            value = param.default
        if value is None and param.required:
            raise ConnectorConfigError(
                f"{self._manifest.name}.{capability_id}: required input "
                f"{param.source!r} (wire name {param.name!r}) is missing"
            )
        return value

    def _build_request(
        self,
        spec: RoutingSpec,
        capability_id: str,
        inputs: dict[str, Any],
        credential: str | None,
        extra_query: dict[str, Any],
    ) -> HTTPRequest:
        path_values: dict[str, Any] = {}
        query: dict[str, Any] = {}
        body: dict[str, Any] = {}
        headers: dict[str, str] = dict(spec.headers)

        for param in spec.params:
            value = self._param_value(param, inputs, capability_id)
            if value is None:
                continue
            if param.location is ParamLocation.PATH:
                path_values[param.name] = value
            elif param.location is ParamLocation.QUERY:
                query[param.name] = value
            elif param.location is ParamLocation.BODY:
                body[param.name] = value
            else:
                headers[param.name] = str(value)

        try:
            path = spec.render_path(path_values)
        except KeyError as exc:  # pragma: no cover - required-check catches this first
            raise ConnectorConfigError(
                f"{self._manifest.name}.{capability_id}: no value for path token {exc.args[0]!r}"
            ) from None

        query.update(extra_query)
        self._apply_auth(spec, credential, headers, query)

        return HTTPRequest(
            method=spec.method.value,
            url=f"{spec.base_url}{path}",
            headers=headers,
            query=query,
            json_body=body or None,
            timeout_seconds=spec.timeout_seconds,
        )

    @staticmethod
    def _apply_auth(
        spec: RoutingSpec,
        credential: str | None,
        headers: dict[str, str],
        query: dict[str, Any],
    ) -> None:
        style = spec.auth.style
        if style is AuthStyle.NONE or credential is None:
            return
        rendered = spec.auth.value_template.replace("{secret}", credential)
        if style is AuthStyle.API_KEY_HEADER:
            headers[str(spec.auth.header)] = rendered
        elif style is AuthStyle.API_KEY_QUERY:
            query[str(spec.auth.query_param)] = rendered
        elif style is AuthStyle.BEARER:
            headers["Authorization"] = f"Bearer {rendered}"
        elif style is AuthStyle.BASIC:
            username = resolve_secret(str(spec.auth.username))
            token = b64encode(f"{username}:{rendered}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"

    # -------------------------------------------------------------- #
    # Execution
    # -------------------------------------------------------------- #

    async def _run(
        self,
        spec: RoutingSpec,
        capability_id: str,
        inputs: dict[str, Any],
        credential: str | None,
        sender: Sender,
        scrub: _Scrubber,
    ) -> dict[str, Any]:
        pagination = spec.pagination
        collected: list[Any] = []
        first_body: Any = None
        extra_query: dict[str, Any] = {}
        pages = 0

        if pagination.style is PaginationStyle.PAGE:
            extra_query[str(pagination.page_param)] = pagination.start_page
        elif pagination.style is PaginationStyle.OFFSET:
            extra_query[str(pagination.offset_param)] = 0
        if pagination.style is not PaginationStyle.NONE and pagination.limit_param:
            if pagination.page_size:
                extra_query[pagination.limit_param] = pagination.page_size

        while True:
            request = self._build_request(spec, capability_id, inputs, credential, extra_query)
            response = await self._send_with_retry(spec, capability_id, request, sender, scrub)

            if response.status_code in spec.response.not_found_statuses:
                if pages == 0:
                    return dict(spec.response.not_found_output)
                break

            if not 200 <= response.status_code < 300:
                raise ConnectorHTTPError(
                    connector=self._manifest.name,
                    capability=capability_id,
                    status_code=response.status_code,
                    detail=scrub(_excerpt(response)),
                )

            pages += 1
            if first_body is None:
                first_body = response.json_body

            if pagination.style is PaginationStyle.NONE:
                break

            page_items = extract_path(response.json_body, str(pagination.items_path))
            if isinstance(page_items, list):
                collected.extend(page_items)
            else:
                page_items = []

            if pages >= pagination.max_pages:
                break

            if pagination.style is PaginationStyle.CURSOR:
                cursor = extract_path(response.json_body, str(pagination.cursor_path))
                if not cursor:
                    break
                extra_query[str(pagination.cursor_param)] = cursor
            elif pagination.style is PaginationStyle.PAGE:
                if not page_items:
                    break
                extra_query[str(pagination.page_param)] = (
                    int(extra_query[str(pagination.page_param)]) + 1
                )
            elif pagination.style is PaginationStyle.OFFSET:
                if not page_items:
                    break
                extra_query[str(pagination.offset_param)] = int(
                    extra_query[str(pagination.offset_param)]
                ) + len(page_items)

        mapped = spec.response.apply(first_body)
        if pagination.style is not PaginationStyle.NONE:
            mapped[pagination.items_key] = collected
        return mapped

    async def _send_with_retry(
        self,
        spec: RoutingSpec,
        capability_id: str,
        request: HTTPRequest,
        sender: Sender,
        scrub: _Scrubber,
    ) -> HTTPResponse:
        retry = spec.retry
        last_error: Exception | None = None

        for attempt in range(1, retry.max_attempts + 1):
            delay = retry.delay_seconds(attempt)
            if delay:
                await self._sleep(delay)

            logger.debug(
                "declarative call %s.%s %s %s (attempt %d/%d)",
                self._manifest.name,
                capability_id,
                request.method,
                scrub(request.url),
                attempt,
                retry.max_attempts,
            )

            try:
                result = sender(request)
                response = await result if inspect.isawaitable(result) else result
            except TimeoutError as exc:
                last_error = exc
                if not retry.retry_on_timeout or attempt == retry.max_attempts:
                    raise ConnectorTransportError(
                        f"{self._manifest.name}.{capability_id}: request timed out after "
                        f"{attempt} attempt(s)"
                    ) from None
                continue
            except ConnectorError:
                raise
            except Exception as exc:  # transport-level failure
                last_error = exc
                if attempt == retry.max_attempts:
                    raise ConnectorTransportError(
                        f"{self._manifest.name}.{capability_id}: transport failure — "
                        f"{scrub(str(exc)) or type(exc).__name__}"
                    ) from None
                continue

            if response.status_code in retry.retry_on_status and attempt < retry.max_attempts:
                logger.debug(
                    "declarative call %s.%s got retryable status %d; retrying",
                    self._manifest.name,
                    capability_id,
                    response.status_code,
                )
                continue

            return response

        # Unreachable: the loop either returns or raises. Kept for type safety.
        raise ConnectorTransportError(  # pragma: no cover
            f"{self._manifest.name}.{capability_id}: retries exhausted "
            f"({scrub(str(last_error)) if last_error else 'no response'})"
        )


def _excerpt(response: HTTPResponse) -> str:
    text = response.text or ""
    if not text and response.json_body is not None:
        text = str(response.json_body)
    return text[:_BODY_EXCERPT_CHARS]


# ---------------------------------------------------------------------------
# Live sender — the only place this package touches the network
# ---------------------------------------------------------------------------


async def _httpx_sender(request: HTTPRequest) -> HTTPResponse:
    """Perform the real HTTP call. Reached only when mock mode is OFF."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - depends on the install profile
        raise ConnectorTransportError(
            "httpx is required for live declarative connector calls; install it or run "
            "with BTAGENT_MOCK_CONNECTORS=true"
        ) from exc

    async with httpx.AsyncClient(timeout=request.timeout_seconds) as client:
        raw = await client.request(
            request.method,
            request.url,
            headers=request.headers,
            params=request.query or None,
            json=request.json_body,
        )

    body: Any = None
    try:
        body = raw.json()
    except Exception:
        body = None
    return HTTPResponse(status_code=raw.status_code, json_body=body, text=raw.text)


__all__ = [
    "MOCK_CREDENTIAL",
    "ConnectorAuthError",
    "ConnectorConfigError",
    "ConnectorError",
    "ConnectorHTTPError",
    "ConnectorTransportError",
    "DeclarativeConnector",
    "HTTPRequest",
    "HTTPResponse",
    "Sender",
    "mock_mode_enabled",
]
