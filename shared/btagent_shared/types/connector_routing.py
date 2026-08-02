"""Declarative routing spec — describe an HTTP connector instead of coding it.

This is the BTagent take on n8n's declarative-node architecture (#101):
roughly 80% of security-tool integrations are "call this REST endpoint,
pass these params, pull these fields out of the JSON". Those need no
Python at all — a :class:`RoutingSpec` attached to a
:class:`~btagent_shared.types.connector.QueryCapability` /
:class:`~btagent_shared.types.connector.ActionCapability` is enough for
the generic HTTP runner (``btagent_engine.integrations._declarative``)
to execute the call, retry it, page through it, and map the response
onto the node's output fields.

Authoring a new connector therefore becomes a *manifest entry*, not a
new module — which is the precondition for #100's AI-authored
connectors: the authoring target is a validated spec, not arbitrary code.

Hard rules encoded as validation (a bad spec fails at import time, not
at 3am during an incident):

1. **No inline secrets, ever.** ``RoutingAuth.secret_ref`` must be a
   single complete ``${secret:...}`` / ``${env:VAR}`` reference — the
   same reference grammar the credential-reference store already
   enforces. Raw material is rejected. Static headers and constant
   params are checked too, so a secret can't be smuggled in via
   ``headers={"x-apikey": "..."}``.
2. **No credentials in the URL.** ``https://user:pass@host`` is rejected.
3. **Plaintext only for loopback.** ``http://`` is allowed for
   localhost/127.0.0.1 (on-prem dev appliances); everything else must
   be ``https://``.
4. **Path templating is closed.** Every ``{token}`` in ``path`` must
   have a matching ``location="path"`` param and vice versa — a typo
   can't silently produce a request to ``/ip_addresses/%7Bip%7D``.

The spec is Pydantic-only and lives in ``shared`` so the engine (which
executes it), the agents package (which introspects it) and the backend
catalog API (which serves it) all read the same types.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any
from urllib.parse import quote, urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

from btagent_shared.utils.secrets import SECRET_PATTERN, is_secret_reference

# ---------------------------------------------------------------------------
# JSON path — the tiny grammar used by request/response mapping
# ---------------------------------------------------------------------------

#: A dotted path with optional numeric indices and ``[*]`` list projection:
#:   ``data.attributes.reputation``
#:   ``data.0.id``
#:   ``data.attributes.popular_threat_classification.popular_threat_name[*].value``
JSON_PATH_RE = re.compile(r"^[A-Za-z0-9_\-]+(\[\*\])?(\.[A-Za-z0-9_\-]+(\[\*\])?)*$")


def _walk(node: Any, segments: list[str]) -> Any:
    if not segments:
        return node

    segment, rest = segments[0], segments[1:]
    project = segment.endswith("[*]")
    key = segment[:-3] if project else segment

    if isinstance(node, dict):
        if key not in node:
            return None
        value = node[key]
    elif isinstance(node, list):
        if not key.isdigit():
            return None
        index = int(key)
        if index >= len(node):
            return None
        value = node[index]
    else:
        return None

    if project:
        if not isinstance(value, list):
            return None
        projected = [got for item in value if (got := _walk(item, rest)) is not None]
        return projected

    return _walk(value, rest)


def extract_path(data: Any, path: str) -> Any:
    """Read *path* out of a decoded JSON body.

    Returns ``None`` when any segment is missing — callers treat that as
    "field absent", which lets the output model's own default apply
    rather than forcing every connector to declare every field.
    """
    if not path:
        return data
    return _walk(data, path.split("."))


def _contains_secret_reference(value: str) -> bool:
    return SECRET_PATTERN.search(value) is not None


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HTTPMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class AuthStyle(StrEnum):
    """How the resolved credential is attached to the request.

    Mirrors the subset of :class:`~btagent_shared.types.connector.CredentialType`
    that a generic HTTP runner can apply without vendor code. OAuth2 /
    SigV4 / mTLS connectors stay programmatic for now.
    """

    NONE = "none"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BEARER = "bearer"
    BASIC = "basic"


class ParamLocation(StrEnum):
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"


class PaginationStyle(StrEnum):
    NONE = "none"
    CURSOR = "cursor"
    PAGE = "page"
    OFFSET = "offset"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class RoutingAuth(BaseModel):
    """Credential placement for a declarative request.

    ``secret_ref`` is a *reference*, never material: the runner resolves
    it through :func:`btagent_shared.utils.secrets.resolve_secret` at
    call time and scrubs the resolved value out of every log line and
    error message it produces.
    """

    model_config = ConfigDict(extra="forbid")

    style: AuthStyle = Field(default=AuthStyle.NONE)
    secret_ref: str | None = Field(
        default=None,
        description="Secret reference for the credential, e.g. "
        "'${secret:vault:connectors/virustotal#api_key}' or '${env:VIRUSTOTAL_API_KEY}'. "
        "Raw secret material is rejected by validation.",
    )
    header: str | None = Field(
        default=None,
        description="Header name for style=api_key_header (e.g. 'x-apikey').",
    )
    query_param: str | None = Field(
        default=None,
        description="Query parameter name for style=api_key_query (e.g. 'apikey').",
    )
    username: str | None = Field(
        default=None,
        description="Username for style=basic. May itself be a ${...} reference; "
        "the password always comes from secret_ref.",
    )
    value_template: str = Field(
        default="{secret}",
        description="Template for the header/query value; '{secret}' is replaced with "
        "the resolved credential (e.g. 'Token {secret}' for vendors that prefix it).",
    )

    @model_validator(mode="after")
    def _check(self) -> RoutingAuth:
        if self.style is AuthStyle.NONE:
            if self.secret_ref is not None:
                raise ValueError("auth.style='none' must not declare a secret_ref")
            return self

        if not self.secret_ref:
            raise ValueError(f"auth.style={self.style.value!r} requires a secret_ref")
        if not is_secret_reference(self.secret_ref):
            raise ValueError(
                "auth.secret_ref must be a single ${secret:...} / ${env:VAR} reference — "
                "inline secret material is never allowed in a connector manifest"
            )
        if "{secret}" not in self.value_template:
            raise ValueError("auth.value_template must contain the '{secret}' placeholder")

        if self.style is AuthStyle.API_KEY_HEADER and not self.header:
            raise ValueError("auth.style='api_key_header' requires a header name")
        if self.style is AuthStyle.API_KEY_QUERY and not self.query_param:
            raise ValueError("auth.style='api_key_query' requires a query_param name")
        if self.style is AuthStyle.BASIC and not self.username:
            raise ValueError("auth.style='basic' requires a username")
        return self


# ---------------------------------------------------------------------------
# Request params
# ---------------------------------------------------------------------------


class RequestParam(BaseModel):
    """One wire parameter, sourced from a tool input or a constant."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Wire name (path token, query key, body key, header).")
    location: ParamLocation = Field(default=ParamLocation.QUERY)
    source: str | None = Field(
        default=None,
        description="Name of the field on the capability's input model to read. "
        "Mutually exclusive with `value`.",
    )
    value: Any = Field(
        default=None,
        description="Constant value for this parameter. Mutually exclusive with `source`. "
        "Must not contain a secret reference — credentials go through `auth`.",
    )
    required: bool = Field(
        default=False,
        description="If True the runner refuses to build the request when the input "
        "field is missing/None. Path params are implicitly required.",
    )
    default: Any = Field(
        default=None,
        description="Fallback used when the sourced input field is absent or None.",
    )

    @model_validator(mode="after")
    def _check(self) -> RequestParam:
        if not self.name.strip():
            raise ValueError("param.name must be non-empty")
        has_source = self.source is not None
        has_value = self.value is not None
        if has_source == has_value:
            raise ValueError(f"param {self.name!r}: exactly one of `source` or `value` is required")
        if has_value and isinstance(self.value, str) and _contains_secret_reference(self.value):
            raise ValueError(
                f"param {self.name!r}: secret references are not allowed in constant "
                "param values — declare credentials in `auth` so the runner can redact them"
            )
        if self.location is ParamLocation.PATH and not self.required:
            # Path tokens can't be omitted; normalise rather than nag.
            self.required = True
        return self


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class PaginationSpec(BaseModel):
    """How to walk multi-page responses.

    ``items_path`` is the JSON path to the per-page list; the runner
    concatenates those lists and returns them under ``items_key``.
    """

    model_config = ConfigDict(extra="forbid")

    style: PaginationStyle = Field(default=PaginationStyle.NONE)
    items_path: str | None = Field(default=None, description="JSON path to the per-page list.")
    items_key: str = Field(default="items", description="Output key for the accumulated list.")
    cursor_param: str | None = Field(
        default=None, description="Query param carrying the cursor (style=cursor)."
    )
    cursor_path: str | None = Field(
        default=None, description="JSON path to the next cursor in the response (style=cursor)."
    )
    page_param: str | None = Field(default=None, description="Query param for the page number.")
    offset_param: str | None = Field(default=None, description="Query param for the row offset.")
    limit_param: str | None = Field(default=None, description="Query param for the page size.")
    page_size: int | None = Field(default=None, ge=1, le=10_000)
    start_page: int = Field(default=1, ge=0)
    max_pages: int = Field(
        default=10,
        ge=1,
        le=1_000,
        description="Hard stop so a broken cursor can't spin forever.",
    )

    @model_validator(mode="after")
    def _check(self) -> PaginationSpec:
        if self.style is PaginationStyle.NONE:
            return self
        if not self.items_path:
            raise ValueError(f"pagination.style={self.style.value!r} requires items_path")
        if not JSON_PATH_RE.match(self.items_path):
            raise ValueError(f"pagination.items_path {self.items_path!r} is not a valid JSON path")
        if self.style is PaginationStyle.CURSOR:
            if not self.cursor_param or not self.cursor_path:
                raise ValueError("pagination.style='cursor' requires cursor_param and cursor_path")
            if not JSON_PATH_RE.match(self.cursor_path):
                raise ValueError(
                    f"pagination.cursor_path {self.cursor_path!r} is not a valid JSON path"
                )
        if self.style is PaginationStyle.PAGE and not self.page_param:
            raise ValueError("pagination.style='page' requires page_param")
        if self.style is PaginationStyle.OFFSET:
            if not self.offset_param:
                raise ValueError("pagination.style='offset' requires offset_param")
            if not self.page_size:
                raise ValueError("pagination.style='offset' requires page_size")
        return self


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------


class RetryPolicy(BaseModel):
    """Exponential backoff for transient failures.

    Defaults are deliberately conservative: 3 attempts, 200ms initial
    backoff, doubling, capped at 10s. Only idempotent-ish failures
    (429 + 5xx + timeouts) are retried — a 4xx that isn't 429 is a
    request bug and retrying it just burns quota.
    """

    model_config = ConfigDict(extra="forbid")

    max_attempts: int = Field(default=3, ge=1, le=10)
    backoff_initial_ms: int = Field(default=200, ge=0, le=60_000)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    backoff_max_ms: int = Field(default=10_000, ge=0, le=300_000)
    retry_on_status: list[int] = Field(default_factory=lambda: [429, 500, 502, 503, 504])
    retry_on_timeout: bool = Field(default=True)

    @model_validator(mode="after")
    def _check(self) -> RetryPolicy:
        bad = [s for s in self.retry_on_status if not 400 <= s <= 599]
        if bad:
            raise ValueError(f"retry.retry_on_status entries must be 4xx/5xx; got {bad}")
        return self

    def delay_seconds(self, attempt: int) -> float:
        """Backoff before *attempt* (1-based: attempt 2 is the first retry)."""
        if attempt <= 1:
            return 0.0
        raw_ms = self.backoff_initial_ms * (self.backoff_multiplier ** (attempt - 2))
        return min(raw_ms, self.backoff_max_ms) / 1000.0


# ---------------------------------------------------------------------------
# Response mapping
# ---------------------------------------------------------------------------


class ResponseMapping(BaseModel):
    """JSON path -> output field mapping.

    ``root`` narrows the document once (``data.attributes``) so the
    per-field paths stay short. Absent paths are omitted from the mapped
    output entirely, which lets the output model's declared default win.
    """

    model_config = ConfigDict(extra="forbid")

    root: str | None = Field(default=None, description="JSON path applied before `fields`.")
    fields: dict[str, str] = Field(
        default_factory=dict,
        description="output_field -> JSON path (relative to `root`).",
    )
    constants: dict[str, Any] = Field(
        default_factory=dict,
        description="Output fields set unconditionally on a successful response "
        "(e.g. {'seen': true}).",
    )
    not_found_statuses: list[int] = Field(
        default_factory=list,
        description="Statuses that mean 'no record' rather than an error (VirusTotal "
        "answers 404 for an unknown indicator).",
    )
    not_found_output: dict[str, Any] = Field(
        default_factory=dict,
        description="Output returned verbatim for a not-found status.",
    )

    @model_validator(mode="after")
    def _check(self) -> ResponseMapping:
        if not self.fields and not self.constants:
            raise ValueError("response mapping must declare at least one field or constant")
        if self.root is not None and not JSON_PATH_RE.match(self.root):
            raise ValueError(f"response.root {self.root!r} is not a valid JSON path")
        for out_field, path in self.fields.items():
            if not JSON_PATH_RE.match(path):
                raise ValueError(
                    f"response.fields[{out_field!r}] path {path!r} is not a valid JSON path"
                )
        bad = [s for s in self.not_found_statuses if not 100 <= s <= 599]
        if bad:
            raise ValueError(f"response.not_found_statuses must be HTTP statuses; got {bad}")
        if self.not_found_output and not self.not_found_statuses:
            raise ValueError("response.not_found_output declared without not_found_statuses")
        return self

    def apply(self, body: Any) -> dict[str, Any]:
        """Map a decoded JSON body onto output fields."""
        scope = extract_path(body, self.root) if self.root else body
        mapped: dict[str, Any] = dict(self.constants)
        for out_field, path in self.fields.items():
            value = extract_path(scope, path)
            if value is not None:
                mapped[out_field] = value
        return mapped


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

_PATH_TOKEN_RE = re.compile(r"\{([A-Za-z0-9_\-]+)\}")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class RoutingSpec(BaseModel):
    """Everything the generic HTTP runner needs to execute a capability."""

    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(..., description="Scheme + host + optional base path, no trailing slash.")
    method: HTTPMethod = Field(default=HTTPMethod.GET)
    path: str = Field(
        default="/", description="Path template appended to base_url, e.g. '/ips/{ip}'."
    )
    params: list[RequestParam] = Field(default_factory=list)
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Static headers (Accept, User-Agent, ...). Secrets are rejected here.",
    )
    auth: RoutingAuth = Field(default_factory=RoutingAuth)
    pagination: PaginationSpec = Field(default_factory=PaginationSpec)
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    response: ResponseMapping = Field(...)
    timeout_seconds: float = Field(default=15.0, gt=0.0, le=300.0)
    live_egress_approved: bool = Field(
        default=False,
        description="Mock-first gate. While False the runner refuses to make a real "
        "call when BTAGENT_MOCK_CONNECTORS is off, mirroring the NotImplementedError "
        "stance every programmatic connector already takes. Flip it per connector once "
        "the live endpoint + credential wiring have been reviewed.",
    )

    # -------------------------------------------------------------- #
    # Validation
    # -------------------------------------------------------------- #

    @model_validator(mode="after")
    def _check(self) -> RoutingSpec:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"base_url must be http(s); got {self.base_url!r}")
        if parsed.username or parsed.password or "@" in parsed.netloc:
            raise ValueError("base_url must not embed credentials")
        if not parsed.hostname:
            raise ValueError(f"base_url has no host: {self.base_url!r}")
        if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
            raise ValueError(
                f"base_url {self.base_url!r} is plaintext http; only loopback hosts may "
                "skip TLS. Use https:// for remote endpoints."
            )
        if self.base_url.endswith("/"):
            raise ValueError("base_url must not end with '/' (the path template supplies it)")
        if _contains_secret_reference(self.base_url):
            raise ValueError("base_url must not contain a secret reference")

        if not self.path.startswith("/"):
            raise ValueError(f"path must start with '/'; got {self.path!r}")

        # Path templating is closed in both directions.
        tokens = set(_PATH_TOKEN_RE.findall(self.path))
        leftovers = re.sub(_PATH_TOKEN_RE, "", self.path)
        if "{" in leftovers or "}" in leftovers:
            raise ValueError(f"path {self.path!r} has malformed '{{token}}' templating")
        path_params = {p.name for p in self.params if p.location is ParamLocation.PATH}
        if tokens - path_params:
            raise ValueError(
                f"path template references undeclared params: {sorted(tokens - path_params)}"
            )
        if path_params - tokens:
            raise ValueError(
                f"path params declared but not used in the path: {sorted(path_params - tokens)}"
            )

        names: set[tuple[str, str]] = set()
        for param in self.params:
            key = (param.location.value, param.name)
            if key in names:
                raise ValueError(f"duplicate param {param.name!r} in {param.location.value}")
            names.add(key)

        for header, value in self.headers.items():
            if _contains_secret_reference(value):
                raise ValueError(
                    f"static header {header!r} contains a secret reference — declare it in "
                    "`auth` so the runner can redact the resolved value"
                )
            if self.auth.header and header.lower() == self.auth.header.lower():
                raise ValueError(
                    f"static header {header!r} collides with the auth header; the "
                    "credential would be overwritten"
                )

        if self.auth.style is AuthStyle.API_KEY_QUERY:
            collide = [
                p.name
                for p in self.params
                if p.location is ParamLocation.QUERY and p.name == self.auth.query_param
            ]
            if collide:
                raise ValueError(
                    f"query param {self.auth.query_param!r} collides with the auth query param"
                )

        if self.method is HTTPMethod.GET:
            body_params = [p.name for p in self.params if p.location is ParamLocation.BODY]
            if body_params:
                raise ValueError(f"GET requests cannot carry body params: {sorted(body_params)}")

        return self

    # -------------------------------------------------------------- #
    # Helpers
    # -------------------------------------------------------------- #

    def render_path(self, values: dict[str, Any]) -> str:
        """Substitute ``{token}`` path params, URL-encoding each value (E3).

        Path values reach here from attacker-influenced sources (IOC values
        pulled from TAXII feeds / report text). Interpolating them raw let a
        value like ``x/../../../users/me`` normalize to a different endpoint,
        and a bare ``?`` opened an undeclared query string. Every value is
        percent-encoded with **no safe characters** — ``/``, ``.``, ``?``, ``#``
        and ``%`` are all escaped — so a path param can only ever be a single
        opaque segment, never restructure the URL. Raises on a missing token.
        """

        def _sub(match: re.Match[str]) -> str:
            token = match.group(1)
            if token not in values or values[token] is None:
                raise KeyError(token)
            return quote(str(values[token]), safe="")

        return _PATH_TOKEN_RE.sub(_sub, self.path)

    def params_at(self, location: ParamLocation) -> list[RequestParam]:
        return [p for p in self.params if p.location is location]


__all__ = [
    "JSON_PATH_RE",
    "AuthStyle",
    "HTTPMethod",
    "PaginationSpec",
    "PaginationStyle",
    "ParamLocation",
    "RequestParam",
    "ResponseMapping",
    "RetryPolicy",
    "RoutingAuth",
    "RoutingSpec",
    "extract_path",
]
