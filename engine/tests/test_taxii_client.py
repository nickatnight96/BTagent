"""Tests for the mock-first TAXII 2.1 client (#105 / UC-2.1).

Covers the fixture collections, the ``added_after`` cursor, config validation
(including the "no credentials in the URL" rule), auth-header shaping, and the
secret-scrubbing guarantee. Zero network egress: every assertion runs with
``BTAGENT_MOCK_CONNECTORS=true`` except the ones that deliberately check the
live path *fails before* opening a socket.
"""

from __future__ import annotations

import pytest

from btagent_engine.integrations.taxii import (
    AUTH_BASIC,
    AUTH_BEARER,
    MOCK_DEFAULT_COLLECTION_ID,
    MOCK_PHISHING_COLLECTION_ID,
    TaxiiClient,
    TaxiiConfigError,
    TaxiiHTTPError,
    mock_collection_ids,
    normalize_server_url,
    scrub_secrets,
)

SERVER = "https://taxii.example.test/api1"


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


def _client(**kwargs) -> TaxiiClient:
    return TaxiiClient(server_url=SERVER, **kwargs)


# --------------------------------------------------------------------------- #
# URL / config validation
# --------------------------------------------------------------------------- #


def test_normalize_strips_trailing_slash() -> None:
    assert normalize_server_url("https://taxii.example.test/api1/") == (
        "https://taxii.example.test/api1"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "ftp://taxii.example.test/api1",
        "file:///etc/passwd",
        "https://",
    ],
)
def test_normalize_rejects_non_http_urls(bad: str) -> None:
    with pytest.raises(TaxiiConfigError):
        normalize_server_url(bad)


def test_normalize_rejects_credentials_embedded_in_url() -> None:
    """A URL is config, not a secret store — userinfo would be a back door."""
    with pytest.raises(TaxiiConfigError) as exc:
        normalize_server_url("https://svc:hunter2@taxii.example.test/api1")
    assert "${secret:" in str(exc.value)


def test_client_rejects_unknown_auth_style() -> None:
    with pytest.raises(TaxiiConfigError):
        TaxiiClient(server_url=SERVER, auth_style="mtls-someday")


# --------------------------------------------------------------------------- #
# Mock collections
# --------------------------------------------------------------------------- #


async def test_collections_lists_fixture_collections() -> None:
    collections = await _client().collections()
    assert [c.id for c in collections] == mock_collection_ids()
    assert all(c.can_read for c in collections)
    assert all(not c.can_write for c in collections)


async def test_poll_without_cursor_returns_every_object() -> None:
    result = await _client().poll(MOCK_DEFAULT_COLLECTION_ID)
    assert result.object_count == 3
    assert all(o["type"] == "indicator" for o in result.objects)
    assert result.latest_added == "2026-07-22T08:00:00.000000Z"
    assert result.more_available is False


async def test_poll_with_cursor_returns_only_newer_objects() -> None:
    """The incremental contract: strictly-after, and the cursor advances."""
    first = await _client().poll(MOCK_DEFAULT_COLLECTION_ID)
    second = await _client().poll(MOCK_DEFAULT_COLLECTION_ID, added_after=first.latest_added)
    assert second.object_count == 0
    # An empty poll yields no cursor, so the caller keeps its previous one
    # instead of silently skipping ahead.
    assert second.latest_added is None


async def test_poll_cursor_midway_returns_the_tail() -> None:
    result = await _client().poll(
        MOCK_DEFAULT_COLLECTION_ID, added_after="2026-07-20T08:00:00.000000Z"
    )
    assert result.object_count == 2
    assert result.latest_added == "2026-07-22T08:00:00.000000Z"


async def test_poll_respects_max_objects_and_reports_more() -> None:
    result = await _client().poll(MOCK_DEFAULT_COLLECTION_ID, max_objects=2)
    assert result.object_count == 2
    assert result.more_available is True
    assert result.latest_added == "2026-07-21T08:00:00.000000Z"


async def test_poll_unknown_collection_raises_404() -> None:
    with pytest.raises(TaxiiHTTPError) as exc:
        await _client().poll("collection--does-not-exist")
    assert exc.value.status_code == 404


async def test_poll_requires_a_collection_id() -> None:
    with pytest.raises(TaxiiConfigError):
        await _client().poll("")


async def test_fixtures_carry_tlp_markings_for_the_ingest_path() -> None:
    """TLP is derived downstream from markings — the fixtures must have some."""
    objects = (await _client().poll(MOCK_PHISHING_COLLECTION_ID)).objects
    marked = [o for o in objects if o.get("object_marking_refs")]
    assert marked, "at least one fixture indicator must carry a TLP marking"


# --------------------------------------------------------------------------- #
# Auth + secret hygiene
# --------------------------------------------------------------------------- #


def test_bearer_auth_header_shape() -> None:
    client = _client(credential="tok-abc123", auth_style=AUTH_BEARER)
    assert client._auth_headers()["Authorization"] == "Bearer tok-abc123"


def test_basic_auth_header_is_base64_encoded() -> None:
    client = _client(credential="svc:hunter2", auth_style=AUTH_BASIC)
    assert client._auth_headers()["Authorization"] == "Basic c3ZjOmh1bnRlcjI="


def test_auth_header_requires_material_when_style_is_not_none() -> None:
    client = _client(auth_style=AUTH_BEARER)
    with pytest.raises(TaxiiConfigError):
        client._auth_headers()


# --------------------------------------------------------------------------- #
# Live pagination logic — exercised with a stubbed transport, still zero egress
# --------------------------------------------------------------------------- #


def _stub_transport(client: TaxiiClient, pages, seen):
    async def fake_get(url, *, params):
        seen.append(dict(params))
        return pages.pop(0)

    client._get = fake_get  # type: ignore[method-assign]


async def test_pagination_walks_more_and_next(monkeypatch) -> None:
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    client = _client()
    pages = [
        (
            {"objects": [{"type": "indicator", "id": "indicator--1"}], "more": True, "next": "c1"},
            {"x-taxii-date-added-last": "2026-07-20T00:00:00.000000Z"},
        ),
        (
            {"objects": [{"type": "indicator", "id": "indicator--2"}], "more": False},
            {"x-taxii-date-added-last": "2026-07-21T00:00:00.000000Z"},
        ),
    ]
    seen: list[dict] = []
    _stub_transport(client, pages, seen)

    result = await client.poll(
        MOCK_DEFAULT_COLLECTION_ID, added_after="2026-07-19T00:00:00.000000Z"
    )

    assert result.pages_fetched == 2
    assert result.object_count == 2
    assert result.latest_added == "2026-07-21T00:00:00.000000Z"
    assert result.more_available is False
    # The cursor rides every request; the continuation token only the second.
    assert seen[0]["added_after"] == "2026-07-19T00:00:00.000000Z"
    assert "next" not in seen[0]
    assert seen[1]["next"] == "c1"


async def test_pagination_stops_when_more_is_true_but_next_is_missing(monkeypatch) -> None:
    """A server that claims more without a token must not spin the loop."""
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    client = _client()
    pages = [({"objects": [], "more": True}, {})]
    seen: list[dict] = []
    _stub_transport(client, pages, seen)

    result = await client.poll(MOCK_DEFAULT_COLLECTION_ID)
    assert result.pages_fetched == 1
    assert result.more_available is True


async def test_cursor_falls_back_to_newest_timestamp_without_the_header(monkeypatch) -> None:
    """``X-TAXII-Date-Added-Last`` is SHOULD, not MUST — still make progress."""
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    client = _client()
    pages = [
        (
            {
                "objects": [
                    {"type": "indicator", "id": "indicator--1", "modified": "2026-07-01T00:00:00Z"},
                    {"type": "indicator", "id": "indicator--2", "modified": "2026-07-05T00:00:00Z"},
                ],
                "more": False,
            },
            {},
        )
    ]
    _stub_transport(client, pages, [])

    result = await client.poll(MOCK_DEFAULT_COLLECTION_ID)
    assert result.latest_added == "2026-07-05T00:00:00Z"


def test_scrub_removes_known_credential_material() -> None:
    text = "HTTP 401 for token super-secret-token-value"
    scrubbed = scrub_secrets(text, "super-secret-token-value")
    assert "super-secret-token-value" not in scrubbed
    assert "[REDACTED:credential]" in scrubbed


def test_client_scrubber_is_bound_to_its_credential() -> None:
    client = _client(credential="super-secret-token-value", auth_style=AUTH_BEARER)
    assert "super-secret-token-value" not in client._scrub(
        "boom: super-secret-token-value rejected"
    )


# --------------------------------------------------------------------------- #
# E11: URL policy matches the sibling RoutingSpec — https + no link-local.
# --------------------------------------------------------------------------- #


def test_normalize_requires_https_for_remote_hosts() -> None:
    with pytest.raises(TaxiiConfigError, match="plaintext http"):
        normalize_server_url("http://taxii.example.test/api1")


def test_normalize_allows_http_for_loopback() -> None:
    assert normalize_server_url("http://localhost:8080/api1") == "http://localhost:8080/api1"
    assert normalize_server_url("http://127.0.0.1/api1") == "http://127.0.0.1/api1"


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/api1",
        "http://[fe80::1]/api1",
    ],
)
def test_normalize_rejects_link_local_metadata_targets(url: str) -> None:
    with pytest.raises(TaxiiConfigError, match="link-local"):
        normalize_server_url(url)
