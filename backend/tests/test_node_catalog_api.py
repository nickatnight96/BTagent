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
