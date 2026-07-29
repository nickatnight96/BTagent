"""Validation contract for the declarative routing spec (#101).

A connector authored as a manifest entry is only as safe as the schema
that accepts it — these tests pin the rejections that keep an
AI-authored (or hand-authored) spec from shipping an inline credential,
a plaintext egress, or a path template that silently requests
``/ips/%7Bip%7D``.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.connector import QueryCapability
from btagent_shared.types.connector_routing import (
    AuthStyle,
    HTTPMethod,
    PaginationSpec,
    PaginationStyle,
    ParamLocation,
    RequestParam,
    ResponseMapping,
    RetryPolicy,
    RoutingAuth,
    RoutingSpec,
    extract_path,
)
from pydantic import ValidationError

API_KEY_REF = "${env:TEST_CONNECTOR_KEY}"


def _auth() -> RoutingAuth:
    return RoutingAuth(style=AuthStyle.API_KEY_HEADER, header="x-apikey", secret_ref=API_KEY_REF)


def _response() -> ResponseMapping:
    return ResponseMapping(fields={"value": "data.value"})


def _spec(**overrides) -> RoutingSpec:
    kwargs = {
        "base_url": "https://api.example.com/v1",
        "path": "/things/{thing_id}",
        "params": [RequestParam(name="thing_id", source="thing_id", location=ParamLocation.PATH)],
        "auth": _auth(),
        "response": _response(),
    }
    kwargs.update(overrides)
    return RoutingSpec(**kwargs)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_minimal_valid_spec_builds():
    spec = _spec()
    assert spec.method is HTTPMethod.GET
    assert spec.live_egress_approved is False  # mock-first by default
    assert spec.render_path({"thing_id": "abc"}) == "/things/abc"


def test_capability_reports_declarative():
    declarative = QueryCapability(id="q", routing=_spec())
    programmatic = QueryCapability(id="q")
    assert declarative.is_declarative is True
    assert programmatic.is_declarative is False


def test_path_params_helper_filters_by_location():
    spec = _spec()
    assert [p.name for p in spec.params_at(ParamLocation.PATH)] == ["thing_id"]
    assert spec.params_at(ParamLocation.QUERY) == []


# --------------------------------------------------------------------------- #
# Secrets are references, never material
# --------------------------------------------------------------------------- #


def test_inline_secret_material_is_rejected():
    with pytest.raises(ValidationError, match="inline secret material"):
        RoutingAuth(
            style=AuthStyle.API_KEY_HEADER,
            header="x-apikey",
            secret_ref="d41d8cd98f00b204e9800998ecf8427e",
        )


def test_partial_reference_is_rejected():
    with pytest.raises(ValidationError, match="inline secret material"):
        RoutingAuth(
            style=AuthStyle.BEARER,
            secret_ref="Bearer ${env:TEST_CONNECTOR_KEY}",
        )


def test_vault_reference_is_accepted():
    auth = RoutingAuth(
        style=AuthStyle.BEARER,
        secret_ref="${secret:vault:connectors/example#token}",
    )
    assert auth.secret_ref.startswith("${secret:vault:")


def test_auth_style_requires_its_placement_field():
    with pytest.raises(ValidationError, match="requires a header name"):
        RoutingAuth(style=AuthStyle.API_KEY_HEADER, secret_ref=API_KEY_REF)
    with pytest.raises(ValidationError, match="requires a query_param name"):
        RoutingAuth(style=AuthStyle.API_KEY_QUERY, secret_ref=API_KEY_REF)
    with pytest.raises(ValidationError, match="requires a username"):
        RoutingAuth(style=AuthStyle.BASIC, secret_ref=API_KEY_REF)


def test_auth_requires_a_secret_ref_unless_style_is_none():
    with pytest.raises(ValidationError, match="requires a secret_ref"):
        RoutingAuth(style=AuthStyle.BEARER)
    assert RoutingAuth().style is AuthStyle.NONE


def test_style_none_must_not_carry_a_secret_ref():
    with pytest.raises(ValidationError, match="must not declare a secret_ref"):
        RoutingAuth(style=AuthStyle.NONE, secret_ref=API_KEY_REF)


def test_value_template_must_keep_the_placeholder():
    with pytest.raises(ValidationError, match=r"\{secret\}"):
        RoutingAuth(
            style=AuthStyle.API_KEY_HEADER,
            header="x-apikey",
            secret_ref=API_KEY_REF,
            value_template="Token abc",
        )


def test_secret_cannot_be_smuggled_through_a_static_header():
    with pytest.raises(ValidationError, match="contains a secret reference"):
        _spec(headers={"x-backdoor": "${env:TEST_CONNECTOR_KEY}"})


def test_secret_cannot_be_smuggled_through_a_constant_param():
    with pytest.raises(ValidationError, match="secret references are not allowed"):
        RequestParam(name="key", value="${env:TEST_CONNECTOR_KEY}")


def test_static_header_may_not_shadow_the_auth_header():
    with pytest.raises(ValidationError, match="collides with the auth header"):
        _spec(headers={"X-ApiKey": "static"})


def test_query_param_may_not_shadow_the_auth_query_param():
    auth = RoutingAuth(style=AuthStyle.API_KEY_QUERY, query_param="apikey", secret_ref=API_KEY_REF)
    with pytest.raises(ValidationError, match="collides with the auth query param"):
        _spec(
            auth=auth,
            params=[
                RequestParam(name="thing_id", source="thing_id", location=ParamLocation.PATH),
                RequestParam(name="apikey", source="apikey", location=ParamLocation.QUERY),
            ],
        )


# --------------------------------------------------------------------------- #
# URL hygiene
# --------------------------------------------------------------------------- #


def test_plaintext_http_is_rejected_for_remote_hosts():
    with pytest.raises(ValidationError, match="plaintext http"):
        _spec(base_url="http://api.example.com/v1")


def test_plaintext_http_is_allowed_for_loopback():
    spec = _spec(base_url="http://localhost:8443/api")
    assert spec.base_url.startswith("http://localhost")


def test_credentials_in_the_url_are_rejected():
    with pytest.raises(ValidationError, match="must not embed credentials"):
        _spec(base_url="https://user:hunter2@api.example.com/v1")


def test_non_http_scheme_is_rejected():
    with pytest.raises(ValidationError, match="must be http"):
        _spec(base_url="ftp://api.example.com")


def test_trailing_slash_is_rejected():
    with pytest.raises(ValidationError, match="must not end with"):
        _spec(base_url="https://api.example.com/v1/")


# --------------------------------------------------------------------------- #
# Path templating is closed in both directions
# --------------------------------------------------------------------------- #


def test_path_token_without_a_declared_param_is_rejected():
    with pytest.raises(ValidationError, match="undeclared params"):
        _spec(path="/things/{thing_id}/{other}")


def test_declared_path_param_missing_from_the_path_is_rejected():
    with pytest.raises(ValidationError, match="not used in the path"):
        _spec(
            path="/things",
            params=[RequestParam(name="thing_id", source="thing_id", location=ParamLocation.PATH)],
        )


def test_path_must_start_with_a_slash():
    with pytest.raises(ValidationError, match="must start with"):
        _spec(path="things", params=[])


def test_render_path_raises_for_a_missing_value():
    with pytest.raises(KeyError):
        _spec().render_path({})


def test_path_params_are_implicitly_required():
    param = RequestParam(name="thing_id", source="thing_id", location=ParamLocation.PATH)
    assert param.required is True


# --------------------------------------------------------------------------- #
# Params
# --------------------------------------------------------------------------- #


def test_param_needs_exactly_one_of_source_or_value():
    with pytest.raises(ValidationError, match="exactly one of"):
        RequestParam(name="limit")
    with pytest.raises(ValidationError, match="exactly one of"):
        RequestParam(name="limit", source="limit", value=10)


def test_duplicate_params_in_the_same_location_are_rejected():
    with pytest.raises(ValidationError, match="duplicate param"):
        _spec(
            path="/things",
            params=[
                RequestParam(name="q", source="a", location=ParamLocation.QUERY),
                RequestParam(name="q", source="b", location=ParamLocation.QUERY),
            ],
        )


def test_get_cannot_declare_body_params():
    with pytest.raises(ValidationError, match="cannot carry body params"):
        _spec(
            path="/things",
            params=[RequestParam(name="filter", source="filter", location=ParamLocation.BODY)],
        )


def test_post_may_declare_body_params():
    spec = _spec(
        method=HTTPMethod.POST,
        path="/things",
        params=[RequestParam(name="filter", source="filter", location=ParamLocation.BODY)],
    )
    assert spec.params_at(ParamLocation.BODY)[0].name == "filter"


# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #


def test_cursor_pagination_requires_cursor_fields():
    with pytest.raises(ValidationError, match="requires cursor_param and cursor_path"):
        PaginationSpec(style=PaginationStyle.CURSOR, items_path="data")


def test_pagination_requires_items_path():
    with pytest.raises(ValidationError, match="requires items_path"):
        PaginationSpec(style=PaginationStyle.PAGE, page_param="page")


def test_offset_pagination_requires_page_size():
    with pytest.raises(ValidationError, match="requires page_size"):
        PaginationSpec(style=PaginationStyle.OFFSET, items_path="data", offset_param="offset")


def test_pagination_rejects_a_bad_items_path():
    with pytest.raises(ValidationError, match="not a valid JSON path"):
        PaginationSpec(style=PaginationStyle.PAGE, page_param="page", items_path="data..items")


def test_max_pages_is_bounded():
    with pytest.raises(ValidationError):
        PaginationSpec(style=PaginationStyle.NONE, max_pages=0)


# --------------------------------------------------------------------------- #
# Retry
# --------------------------------------------------------------------------- #


def test_retry_only_accepts_4xx_5xx_statuses():
    with pytest.raises(ValidationError, match="must be 4xx/5xx"):
        RetryPolicy(retry_on_status=[200])


def test_retry_backoff_is_exponential_and_capped():
    policy = RetryPolicy(
        max_attempts=5, backoff_initial_ms=100, backoff_multiplier=2.0, backoff_max_ms=300
    )
    assert policy.delay_seconds(1) == 0.0  # first attempt is immediate
    assert policy.delay_seconds(2) == pytest.approx(0.1)
    assert policy.delay_seconds(3) == pytest.approx(0.2)
    assert policy.delay_seconds(4) == pytest.approx(0.3)  # capped
    assert policy.delay_seconds(5) == pytest.approx(0.3)


def test_retry_attempts_are_bounded():
    with pytest.raises(ValidationError):
        RetryPolicy(max_attempts=0)


# --------------------------------------------------------------------------- #
# Response mapping
# --------------------------------------------------------------------------- #


def test_response_mapping_needs_fields_or_constants():
    with pytest.raises(ValidationError, match="at least one field or constant"):
        ResponseMapping()


def test_response_mapping_rejects_bad_json_paths():
    with pytest.raises(ValidationError, match="not a valid JSON path"):
        ResponseMapping(fields={"value": "data value"})
    with pytest.raises(ValidationError, match="not a valid JSON path"):
        ResponseMapping(root="data.", fields={"value": "value"})


def test_not_found_output_requires_not_found_statuses():
    with pytest.raises(ValidationError, match="without not_found_statuses"):
        ResponseMapping(fields={"value": "value"}, not_found_output={"seen": False})


def test_not_found_statuses_must_be_http_statuses():
    with pytest.raises(ValidationError, match="must be HTTP statuses"):
        ResponseMapping(fields={"value": "value"}, not_found_statuses=[42])


def test_response_mapping_applies_root_constants_and_omits_missing():
    mapping = ResponseMapping(
        root="data.attributes",
        fields={"value": "value", "absent": "nope"},
        constants={"seen": True},
    )
    mapped = mapping.apply({"data": {"attributes": {"value": 7}}})
    assert mapped == {"seen": True, "value": 7}


def test_response_mapping_on_missing_root_yields_constants_only():
    mapping = ResponseMapping(root="data", fields={"value": "value"}, constants={"seen": True})
    assert mapping.apply({"other": 1}) == {"seen": True}


# --------------------------------------------------------------------------- #
# JSON path extraction
# --------------------------------------------------------------------------- #


def test_extract_path_walks_nested_objects():
    body = {"data": {"attributes": {"stats": {"malicious": 3}}}}
    assert extract_path(body, "data.attributes.stats.malicious") == 3


def test_extract_path_supports_list_indices():
    body = {"data": [{"id": "a"}, {"id": "b"}]}
    assert extract_path(body, "data.1.id") == "b"


def test_extract_path_projects_lists():
    body = {"names": [{"value": "CobaltStrike"}, {"value": "Beacon"}, {"other": 1}]}
    assert extract_path(body, "names[*].value") == ["CobaltStrike", "Beacon"]


def test_extract_path_returns_none_for_missing_segments():
    assert extract_path({"a": 1}, "b.c") is None
    assert extract_path({"a": 1}, "a.b") is None
    assert extract_path(None, "a") is None
