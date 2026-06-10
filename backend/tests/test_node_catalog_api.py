"""Tests for the canvas-palette node catalog endpoint."""

from __future__ import annotations

from httpx import AsyncClient

from tests.helpers import auth_header


async def test_node_catalog_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/workflows/node-catalog")
    assert resp.status_code in (401, 403)


async def test_node_catalog_returns_registered_nodes(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/workflows/node-catalog", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == len(body["items"])
    assert body["total"] > 0

    by_id = {item["id"]: item for item in body["items"]}
    # The manual trigger and a couple of reasoning + integration nodes that
    # the run service imports must all be present in the catalog.
    assert "trigger.manual" in by_id
    assert "reasoning.alert_triage" in by_id
    assert "integration.greynoise.lookup_ip" in by_id

    # Categories are surfaced verbatim so the canvas palette can group.
    assert by_id["trigger.manual"]["category"] == "trigger"
    assert by_id["reasoning.alert_triage"]["category"] == "reasoning"
    assert by_id["integration.greynoise.lookup_ip"]["category"] == "integration"

    # Each entry carries a non-empty human-readable name.
    for item in body["items"]:
        assert item["name"]
        assert "category" in item
        assert "version" in item


async def test_node_catalog_entries_carry_input_schema(client: AsyncClient, analyst_token: str):
    """Every entry exposes its pydantic input model as JSON Schema.

    The editor's typed config form is generated from this — field names,
    types, defaults, required markers, and descriptions all come from the
    node's own input model, so the form can never drift from the engine.
    """
    resp = await client.get("/api/v1/workflows/node-catalog", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    by_id = {item["id"]: item for item in resp.json()["items"]}

    for item in by_id.values():
        assert isinstance(item["input_schema"], dict)

    splunk = by_id["integration.splunk.search"]["input_schema"]
    assert splunk["type"] == "object"
    props = splunk["properties"]
    assert props["query"]["type"] == "string"
    assert props["query"]["description"]
    # Optional fields surface their defaults so the form can show them.
    assert props["earliest_time"]["default"] == "-24h"
    assert props["max_count"]["type"] == "integer"
    # Required list marks which fields have no default.
    assert "query" in splunk["required"]
    assert "earliest_time" not in splunk.get("required", [])
