"""Behaviour contract for the generic declarative HTTP runner (#101).

Zero network egress: every test either runs in mock mode (fixture sender)
or injects its own sender. ``_httpx_sender`` — the only code path in the
package that touches a socket — is monkeypatched to explode in the tests
that could conceivably reach it.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.config import TLP
from btagent_shared.types.connector import (
    ActionCapability,
    AuthStyle,
    ConnectorManifest,
    CredentialType,
    QueryCapability,
    TransportKind,
)
from btagent_shared.types.connector_routing import (
    HTTPMethod,
    PaginationSpec,
    PaginationStyle,
    ParamLocation,
    RequestParam,
    ResponseMapping,
    RetryPolicy,
    RoutingAuth,
    RoutingSpec,
)
from pydantic import BaseModel

from btagent_engine import NodeContext, Runner
from btagent_engine.integrations import _declarative
from btagent_engine.integrations._declarative import (
    MOCK_CREDENTIAL,
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorHTTPError,
    ConnectorTransportError,
    DeclarativeConnector,
    HTTPRequest,
    HTTPResponse,
)
from btagent_engine.middleware import (
    ConnectorPolicyMiddleware,
    ConnectorPolicyViolation,
    PendingHITLApproval,
)
from btagent_engine.node import Node, NodeCategory, NodeMeta

SECRET_ENV = "BTAGENT_TEST_DECLARATIVE_KEY"
SECRET_VALUE = "vt-super-secret-key-9f3c2b1a"
SECRET_REF = "${env:BTAGENT_TEST_DECLARATIVE_KEY}"


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Detonate if any test reaches the live sender."""

    async def _boom(request: HTTPRequest) -> HTTPResponse:  # pragma: no cover
        raise AssertionError(f"live HTTP egress attempted: {request.method} {request.url}")

    monkeypatch.setattr(_declarative, "_httpx_sender", _boom)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


class _Recorder:
    """A scripted sender: records requests, replays queued responses."""

    def __init__(self, *responses: HTTPResponse) -> None:
        self.queue = list(responses)
        self.requests: list[HTTPRequest] = []

    def __call__(self, request: HTTPRequest) -> HTTPResponse:
        self.requests.append(request)
        if len(self.queue) == 1:
            return self.queue[0]
        return self.queue.pop(0)


class _Sleeper:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def _spec(**overrides) -> RoutingSpec:
    kwargs = {
        "base_url": "https://api.example.com/v1",
        "path": "/things/{thing_id}",
        "params": [RequestParam(name="thing_id", source="thing_id", location=ParamLocation.PATH)],
        "auth": RoutingAuth(
            style=AuthStyle.API_KEY_HEADER, header="x-apikey", secret_ref=SECRET_REF
        ),
        "response": ResponseMapping(
            root="data",
            fields={"value": "value"},
            constants={"seen": True},
            not_found_statuses=[404],
            not_found_output={"seen": False},
        ),
        "retry": RetryPolicy(max_attempts=3, backoff_initial_ms=100, backoff_multiplier=2.0),
    }
    kwargs.update(overrides)
    return RoutingSpec(**kwargs)


def _manifest(spec: RoutingSpec | None = None, **capability_kwargs) -> ConnectorManifest:
    return ConnectorManifest(
        name="example",
        version="0.1.0",
        transport=TransportKind.HTTP_REST,
        auth=CredentialType.API_KEY,
        queries=[
            QueryCapability(
                id="get_thing",
                tlp_egress=TLP.AMBER,
                routing=spec if spec is not None else _spec(),
                **capability_kwargs,
            ),
            QueryCapability(id="programmatic_thing", tlp_egress=TLP.AMBER),
        ],
    )


def _ok(value: int = 42) -> HTTPResponse:
    return HTTPResponse(status_code=200, json_body={"data": {"value": value}})


# --------------------------------------------------------------------------- #
# Mock-first
# --------------------------------------------------------------------------- #


async def test_mock_mode_returns_fixture_without_network():
    fixtures = _Recorder(_ok(7))
    connector = DeclarativeConnector(_manifest(), mock_sender=fixtures)

    out = await connector.execute("get_thing", {"thing_id": "abc"})

    assert out == {"seen": True, "value": 7}
    assert fixtures.requests[0].url == "https://api.example.com/v1/things/abc"


async def test_mock_mode_does_not_require_a_resolvable_credential(monkeypatch):
    monkeypatch.delenv(SECRET_ENV, raising=False)
    fixtures = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(), mock_sender=fixtures)

    await connector.execute("get_thing", {"thing_id": "abc"})

    assert fixtures.requests[0].headers["x-apikey"] == MOCK_CREDENTIAL


async def test_mock_mode_without_a_registered_fixture_sender_is_a_config_error():
    connector = DeclarativeConnector(_manifest())
    with pytest.raises(ConnectorConfigError, match="registered no mock sender"):
        await connector.execute("get_thing", {"thing_id": "abc"})


async def test_live_egress_is_refused_until_the_spec_opts_in(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    connector = DeclarativeConnector(_manifest(), mock_sender=_Recorder(_ok()))

    with pytest.raises(NotImplementedError, match="live egress is not approved"):
        await connector.execute("get_thing", {"thing_id": "abc"})


async def test_live_egress_gate_runs_before_the_credential_store_is_touched(monkeypatch):
    """A call we're not allowed to make must not read the vault at all."""
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")

    def _explode(value: str) -> str:  # pragma: no cover - must never run
        raise AssertionError("credential resolved for a refused call")

    monkeypatch.setattr(_declarative, "resolve_secret", _explode)
    connector = DeclarativeConnector(_manifest(), mock_sender=_Recorder(_ok()))

    with pytest.raises(NotImplementedError):
        await connector.execute("get_thing", {"thing_id": "abc"})


async def test_approved_live_spec_uses_the_injected_sender(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    monkeypatch.setenv(SECRET_ENV, SECRET_VALUE)
    live = _Recorder(_ok(11))
    connector = DeclarativeConnector(
        _manifest(_spec(live_egress_approved=True)),
        sender=live,
    )

    out = await connector.execute("get_thing", {"thing_id": "abc"})

    assert out == {"seen": True, "value": 11}
    assert live.requests[0].headers["x-apikey"] == SECRET_VALUE


async def test_live_mode_without_a_resolvable_credential_raises_auth_error(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    monkeypatch.delenv(SECRET_ENV, raising=False)
    connector = DeclarativeConnector(
        _manifest(_spec(live_egress_approved=True)),
        sender=_Recorder(_ok()),
    )

    with pytest.raises(ConnectorAuthError, match="did not resolve"):
        await connector.execute("get_thing", {"thing_id": "abc"})


# --------------------------------------------------------------------------- #
# Auth placement
# --------------------------------------------------------------------------- #


@pytest.fixture
def _key(monkeypatch):
    monkeypatch.setenv(SECRET_ENV, SECRET_VALUE)
    return SECRET_VALUE


async def test_api_key_header_auth(_key):
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(), mock_sender=sender)
    await connector.execute("get_thing", {"thing_id": "a"})
    assert sender.requests[0].headers["x-apikey"] == SECRET_VALUE


async def test_api_key_query_auth(_key):
    spec = _spec(
        auth=RoutingAuth(style=AuthStyle.API_KEY_QUERY, query_param="apikey", secret_ref=SECRET_REF)
    )
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)
    await connector.execute("get_thing", {"thing_id": "a"})
    assert sender.requests[0].query["apikey"] == SECRET_VALUE


async def test_bearer_auth_with_value_template(_key):
    spec = _spec(auth=RoutingAuth(style=AuthStyle.BEARER, secret_ref=SECRET_REF))
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)
    await connector.execute("get_thing", {"thing_id": "a"})
    assert sender.requests[0].headers["Authorization"] == f"Bearer {SECRET_VALUE}"


async def test_basic_auth_encodes_username_and_secret(_key):
    spec = _spec(auth=RoutingAuth(style=AuthStyle.BASIC, username="analyst", secret_ref=SECRET_REF))
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)
    await connector.execute("get_thing", {"thing_id": "a"})

    header = sender.requests[0].headers["Authorization"]
    assert header.startswith("Basic ")
    assert SECRET_VALUE not in header  # base64-encoded, not pasted in


async def test_auth_style_none_sends_no_credential():
    spec = _spec(auth=RoutingAuth())
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)
    await connector.execute("get_thing", {"thing_id": "a"})
    assert "x-apikey" not in sender.requests[0].headers
    assert sender.requests[0].query == {}


# --------------------------------------------------------------------------- #
# Secret redaction — the resolved credential must never surface
# --------------------------------------------------------------------------- #


async def test_secret_never_appears_in_a_connector_http_error(_key):
    """Query-param auth puts the key in the URL — errors must scrub it."""
    spec = _spec(
        auth=RoutingAuth(
            style=AuthStyle.API_KEY_QUERY, query_param="apikey", secret_ref=SECRET_REF
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    sender = _Recorder(
        HTTPResponse(
            status_code=403,
            text=f"forbidden for apikey={SECRET_VALUE}",
        )
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    with pytest.raises(ConnectorHTTPError) as ei:
        await connector.execute("get_thing", {"thing_id": "a"})

    assert SECRET_VALUE not in str(ei.value)
    assert SECRET_VALUE not in ei.value.detail
    assert "[REDACTED:credential]" in ei.value.detail
    assert ei.value.status_code == 403


async def test_secret_never_appears_in_debug_logs(_key, caplog):
    spec = _spec(
        auth=RoutingAuth(style=AuthStyle.API_KEY_QUERY, query_param="apikey", secret_ref=SECRET_REF)
    )
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    with caplog.at_level(logging.DEBUG, logger="btagent.engine.integrations.declarative"):
        await connector.execute("get_thing", {"thing_id": "a"})

    assert caplog.records, "expected the runner to log the outbound call"
    assert SECRET_VALUE not in caplog.text


async def test_secret_never_appears_in_a_transport_error(_key):
    def _raiser(request: HTTPRequest) -> HTTPResponse:
        raise RuntimeError(f"connect failed for apikey={SECRET_VALUE}")

    spec = _spec(retry=RetryPolicy(max_attempts=1))
    connector = DeclarativeConnector(_manifest(spec), mock_sender=_raiser)

    with pytest.raises(ConnectorTransportError) as ei:
        await connector.execute("get_thing", {"thing_id": "a"})

    assert SECRET_VALUE not in str(ei.value)


# --------------------------------------------------------------------------- #
# Status mapping
# --------------------------------------------------------------------------- #


async def test_not_found_status_maps_to_the_declared_output():
    sender = _Recorder(HTTPResponse(status_code=404, json_body={"error": "nope"}))
    connector = DeclarativeConnector(_manifest(), mock_sender=sender)
    assert await connector.execute("get_thing", {"thing_id": "a"}) == {"seen": False}


async def test_non_2xx_maps_to_a_connector_http_error():
    spec = _spec(retry=RetryPolicy(max_attempts=1))
    sender = _Recorder(HTTPResponse(status_code=400, text="bad request: thing_id malformed"))
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    with pytest.raises(ConnectorHTTPError, match="example.get_thing: HTTP 400") as ei:
        await connector.execute("get_thing", {"thing_id": "a"})
    assert "thing_id malformed" in ei.value.detail


async def test_missing_required_input_is_a_config_error():
    connector = DeclarativeConnector(_manifest(), mock_sender=_Recorder(_ok()))
    with pytest.raises(ConnectorConfigError, match="required input 'thing_id'"):
        await connector.execute("get_thing", {})


async def test_unknown_capability_is_a_config_error():
    connector = DeclarativeConnector(_manifest(), mock_sender=_Recorder(_ok()))
    with pytest.raises(ConnectorConfigError, match="no capability 'nope'"):
        await connector.execute("nope", {})


async def test_programmatic_capability_is_refused_by_the_declarative_runner():
    connector = DeclarativeConnector(_manifest(), mock_sender=_Recorder(_ok()))
    with pytest.raises(ConnectorConfigError, match="not declarative"):
        await connector.execute("programmatic_thing", {})


# --------------------------------------------------------------------------- #
# Retries
# --------------------------------------------------------------------------- #


async def test_retryable_status_is_retried_with_exponential_backoff():
    sender = _Recorder(
        HTTPResponse(status_code=429, text="slow down"),
        HTTPResponse(status_code=503, text="unavailable"),
        _ok(5),
    )
    sleeper = _Sleeper()
    connector = DeclarativeConnector(_manifest(), mock_sender=sender, sleep=sleeper)

    out = await connector.execute("get_thing", {"thing_id": "a"})

    assert out == {"seen": True, "value": 5}
    assert len(sender.requests) == 3
    assert sleeper.delays == [pytest.approx(0.1), pytest.approx(0.2)]


async def test_retries_are_exhausted_and_the_last_status_is_raised():
    sender = _Recorder(HTTPResponse(status_code=503, text="unavailable"))
    sleeper = _Sleeper()
    connector = DeclarativeConnector(_manifest(), mock_sender=sender, sleep=sleeper)

    with pytest.raises(ConnectorHTTPError) as ei:
        await connector.execute("get_thing", {"thing_id": "a"})

    assert ei.value.status_code == 503
    assert len(sender.requests) == 3  # max_attempts
    assert len(sleeper.delays) == 2


async def test_non_retryable_status_is_not_retried():
    sender = _Recorder(HTTPResponse(status_code=401, text="unauthorized"))
    connector = DeclarativeConnector(_manifest(), mock_sender=sender, sleep=_Sleeper())

    with pytest.raises(ConnectorHTTPError):
        await connector.execute("get_thing", {"thing_id": "a"})

    assert len(sender.requests) == 1


async def test_transport_failures_are_retried_then_surfaced():
    attempts: list[int] = []

    def _flaky(request: HTTPRequest) -> HTTPResponse:
        attempts.append(1)
        raise ConnectionResetError("peer reset")

    connector = DeclarativeConnector(_manifest(), mock_sender=_flaky, sleep=_Sleeper())

    with pytest.raises(ConnectorTransportError, match="transport failure"):
        await connector.execute("get_thing", {"thing_id": "a"})

    assert len(attempts) == 3


async def test_timeouts_are_retried_then_surfaced():
    attempts: list[int] = []

    def _slow(request: HTTPRequest) -> HTTPResponse:
        attempts.append(1)
        raise TimeoutError

    connector = DeclarativeConnector(_manifest(), mock_sender=_slow, sleep=_Sleeper())

    with pytest.raises(ConnectorTransportError, match="timed out"):
        await connector.execute("get_thing", {"thing_id": "a"})

    assert len(attempts) == 3


async def test_timeout_is_not_retried_when_the_policy_says_so():
    attempts: list[int] = []

    def _slow(request: HTTPRequest) -> HTTPResponse:
        attempts.append(1)
        raise TimeoutError

    spec = _spec(retry=RetryPolicy(max_attempts=3, retry_on_timeout=False))
    connector = DeclarativeConnector(_manifest(spec), mock_sender=_slow, sleep=_Sleeper())

    with pytest.raises(ConnectorTransportError, match="timed out"):
        await connector.execute("get_thing", {"thing_id": "a"})

    assert len(attempts) == 1


# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #


def _paged_spec(pagination: PaginationSpec) -> RoutingSpec:
    return _spec(
        path="/things",
        params=[],
        pagination=pagination,
        response=ResponseMapping(fields={"total": "total"}, constants={"ok": True}),
    )


async def test_cursor_pagination_walks_until_the_cursor_runs_out():
    spec = _paged_spec(
        PaginationSpec(
            style=PaginationStyle.CURSOR,
            items_path="data",
            cursor_param="cursor",
            cursor_path="meta.cursor",
        )
    )
    sender = _Recorder(
        HTTPResponse(
            status_code=200, json_body={"total": 5, "data": [1, 2], "meta": {"cursor": "c1"}}
        ),
        HTTPResponse(status_code=200, json_body={"data": [3, 4], "meta": {"cursor": "c2"}}),
        HTTPResponse(status_code=200, json_body={"data": [5], "meta": {}}),
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    out = await connector.execute("get_thing", {})

    assert out == {"ok": True, "total": 5, "items": [1, 2, 3, 4, 5]}
    assert len(sender.requests) == 3
    assert sender.requests[1].query["cursor"] == "c1"
    assert sender.requests[2].query["cursor"] == "c2"


async def test_cursor_pagination_stops_at_max_pages():
    spec = _paged_spec(
        PaginationSpec(
            style=PaginationStyle.CURSOR,
            items_path="data",
            cursor_param="cursor",
            cursor_path="meta.cursor",
            max_pages=2,
        )
    )
    sender = _Recorder(
        HTTPResponse(status_code=200, json_body={"data": [1], "meta": {"cursor": "always"}})
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    out = await connector.execute("get_thing", {})

    assert out["items"] == [1, 1]
    assert len(sender.requests) == 2


async def test_page_pagination_increments_and_stops_on_an_empty_page():
    spec = _paged_spec(
        PaginationSpec(
            style=PaginationStyle.PAGE,
            items_path="data",
            page_param="page",
            limit_param="per_page",
            page_size=2,
            start_page=1,
        )
    )
    sender = _Recorder(
        HTTPResponse(status_code=200, json_body={"total": 3, "data": ["a", "b"]}),
        HTTPResponse(status_code=200, json_body={"data": ["c"]}),
        HTTPResponse(status_code=200, json_body={"data": []}),
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    out = await connector.execute("get_thing", {})

    assert out == {"ok": True, "total": 3, "items": ["a", "b", "c"]}
    assert [r.query["page"] for r in sender.requests] == [1, 2, 3]
    assert sender.requests[0].query["per_page"] == 2


async def test_offset_pagination_advances_by_the_returned_row_count():
    spec = _paged_spec(
        PaginationSpec(
            style=PaginationStyle.OFFSET,
            items_path="rows",
            offset_param="from",
            limit_param="size",
            page_size=2,
        )
    )
    sender = _Recorder(
        HTTPResponse(status_code=200, json_body={"total": 3, "rows": [1, 2]}),
        HTTPResponse(status_code=200, json_body={"rows": [3]}),
        HTTPResponse(status_code=200, json_body={"rows": []}),
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    out = await connector.execute("get_thing", {})

    assert out["items"] == [1, 2, 3]
    assert [r.query["from"] for r in sender.requests] == [0, 2, 3]


# --------------------------------------------------------------------------- #
# Request shaping
# --------------------------------------------------------------------------- #


async def test_query_body_and_header_params_land_in_the_right_place():
    spec = _spec(
        method=HTTPMethod.POST,
        path="/things",
        params=[
            RequestParam(name="q", source="query", location=ParamLocation.QUERY),
            RequestParam(name="limit", value=25, location=ParamLocation.QUERY),
            RequestParam(name="filter", source="filter", location=ParamLocation.BODY),
            RequestParam(name="X-Trace", source="trace", location=ParamLocation.HEADER),
        ],
        headers={"Accept": "application/json"},
    )
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    await connector.execute(
        "get_thing", {"query": "malware", "filter": {"severity": "high"}, "trace": "t-1"}
    )

    request = sender.requests[0]
    assert request.method == "POST"
    assert request.query["q"] == "malware"
    assert request.query["limit"] == 25
    assert request.json_body == {"filter": {"severity": "high"}}
    assert request.headers["X-Trace"] == "t-1"
    assert request.headers["Accept"] == "application/json"


async def test_optional_params_fall_back_to_their_default_and_omit_when_absent():
    spec = _spec(
        path="/things",
        params=[
            RequestParam(name="limit", source="limit", location=ParamLocation.QUERY, default=50),
            RequestParam(name="cursor", source="cursor", location=ParamLocation.QUERY),
        ],
    )
    sender = _Recorder(_ok())
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    await connector.execute("get_thing", {})

    assert sender.requests[0].query == {"limit": 50}


# --------------------------------------------------------------------------- #
# Policy is NOT bypassed by declarative authoring
# --------------------------------------------------------------------------- #


class _Input(BaseModel):
    thing_id: str = "abc"


class _Output(BaseModel):
    seen: bool = False
    value: int = 0


def _node_class(manifest: ConnectorManifest, connector: DeclarativeConnector) -> type[Node]:
    class _DeclarativeNode(Node[_Input, _Output]):
        meta = NodeMeta(
            id="integration.example.get_thing",
            name="Example: declarative",
            version="0.1.0",
            category=NodeCategory.INTEGRATION,
            description="test node",
        )
        input_schema = _Input
        output_schema = _Output
        manifest_ref = manifest

        async def run(self, input: _Input, ctx: NodeContext) -> _Output:
            mapped = await connector.execute(self.capability_id, input.model_dump())
            return _Output(**mapped)

    _DeclarativeNode.manifest = manifest
    _DeclarativeNode.capability_id = "get_thing"
    return _DeclarativeNode


async def test_declarative_capability_still_hits_the_tlp_gate():
    sender = _Recorder(_ok())
    manifest = _manifest()
    connector = DeclarativeConnector(manifest, mock_sender=sender)
    node = _node_class(manifest, connector)()

    runner = Runner([ConnectorPolicyMiddleware(active_tlp=TLP.RED)])
    with pytest.raises(ConnectorPolicyViolation, match="tlp_egress=amber"):
        await runner.execute(node, _Input(), NodeContext(run_id="r", org_id="o"))

    assert sender.requests == [], "TLP-denied capability must never reach the HTTP runner"


async def test_declarative_capability_still_hits_the_hitl_gate():
    sender = _Recorder(_ok())
    spec = _spec()
    manifest = ConnectorManifest(
        name="example",
        version="0.1.0",
        transport=TransportKind.HTTP_REST,
        auth=CredentialType.API_KEY,
        actions=[
            ActionCapability(
                id="get_thing",
                tlp_egress=TLP.AMBER,
                hitl_required=True,
                routing=spec,
            )
        ],
    )
    connector = DeclarativeConnector(manifest, mock_sender=sender)
    node = _node_class(manifest, connector)()

    runner = Runner([ConnectorPolicyMiddleware(active_tlp=TLP.GREEN)])
    with pytest.raises(PendingHITLApproval):
        await runner.execute(node, _Input(), NodeContext(run_id="r", org_id="o"))

    assert sender.requests == [], "HITL-gated capability must never reach the HTTP runner"


async def test_declarative_capability_runs_once_policy_allows_it():
    sender = _Recorder(_ok(3))
    manifest = _manifest()
    connector = DeclarativeConnector(manifest, mock_sender=sender)
    node = _node_class(manifest, connector)()

    runner = Runner([ConnectorPolicyMiddleware(active_tlp=TLP.GREEN)])
    out = await runner.execute(node, _Input(), NodeContext(run_id="r", org_id="o"))

    assert out.value == 3
    assert len(sender.requests) == 1


# --------------------------------------------------------------------------- #
# P4.4 hardening: E6 httpx timeout, E8 truncation signal, E12 param collision
# --------------------------------------------------------------------------- #


async def test_httpx_timeout_is_treated_as_a_timeout_not_a_generic_retry():
    """E6: httpx.TimeoutException is NOT a builtin TimeoutError subclass, so it
    used to hit the retry-everything branch and ignore retry_on_timeout=False."""
    import httpx

    attempts: list[int] = []

    def _slow(request: HTTPRequest) -> HTTPResponse:
        attempts.append(1)
        raise httpx.ConnectTimeout("timed out")

    spec = _spec(retry=RetryPolicy(max_attempts=3, retry_on_timeout=False))
    connector = DeclarativeConnector(_manifest(spec), mock_sender=_slow, sleep=_Sleeper())

    with pytest.raises(ConnectorTransportError, match="timed out"):
        await connector.execute("get_thing", {"thing_id": "a"})

    # retry_on_timeout=False is honored: exactly one attempt, no duplicate POSTs.
    assert len(attempts) == 1


async def test_pagination_truncation_is_signalled_when_capped():
    """E8: a run stopped by max_pages with more data available is flagged."""
    spec = _paged_spec(
        PaginationSpec(
            style=PaginationStyle.CURSOR,
            items_path="data",
            cursor_param="cursor",
            cursor_path="meta.cursor",
            max_pages=2,
        )
    )
    sender = _Recorder(
        HTTPResponse(status_code=200, json_body={"data": [1], "meta": {"cursor": "more"}})
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    out = await connector.execute("get_thing", {})
    # A cursor still present at the cap → truncated marker is set.
    assert out["_pagination"]["truncated"] is True


async def test_complete_pagination_has_no_truncation_marker():
    spec = _paged_spec(
        PaginationSpec(
            style=PaginationStyle.CURSOR,
            items_path="data",
            cursor_param="cursor",
            cursor_path="meta.cursor",
        )
    )
    sender = _Recorder(
        HTTPResponse(status_code=200, json_body={"data": [1], "meta": {"cursor": "c1"}}),
        HTTPResponse(status_code=200, json_body={"data": [2], "meta": {}}),
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=sender)

    out = await connector.execute("get_thing", {})
    assert "_pagination" not in out


async def test_pagination_control_param_collision_is_refused():
    """E12: a declared query param that collides with a pagination control
    param is a hard-to-see correctness bug — refuse it up front."""
    spec = _spec(
        path="/things",
        params=[RequestParam(name="cursor", source="cursor", location=ParamLocation.QUERY)],
        pagination=PaginationSpec(
            style=PaginationStyle.CURSOR,
            items_path="data",
            cursor_param="cursor",
            cursor_path="meta.cursor",
        ),
        response=ResponseMapping(fields={"total": "total"}),
    )
    connector = DeclarativeConnector(_manifest(spec), mock_sender=_Recorder(_ok()))

    with pytest.raises(ConnectorConfigError, match="collide"):
        await connector.execute("get_thing", {"cursor": "x"})
