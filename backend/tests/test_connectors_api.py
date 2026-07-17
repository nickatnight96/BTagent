"""Tests for the connector catalog API (#100 Layer 3, read-only introspection).

Covers the catalog service (memoised union of engine INTEGRATION-node manifests
and agents-side MCP manifests) and the GET /connectors + GET /connectors/{name}
endpoints: list shape + summary fields, OCSF-emit and has_actions filters,
detail manifest round-trip, 404 for unknown connectors, RBAC + auth.
"""

from __future__ import annotations

from conftest import auth_header

from btagent_backend.services import connector_catalog

# The 9 engine connectors carrying manifests (mirrors the engine coverage test).
EXPECTED = {
    "splunk",
    "sentinel",
    "elastic",
    "crowdstrike",
    "shodan",
    "greynoise",
    "abuseipdb",
    "misp",
    "virustotal",
}

# A sample of MCP-only connectors that must also surface through the catalog
# (identity / email / cloud / ticketing / CNAPP — the Tier-1/Tier-2 fleet).
EXPECTED_MCP_ONLY = {
    "okta",
    "entra",
    "gws",
    "defender_o365",
    "defender_endpoint",
    "sentinelone",
    "zeek",
    "cloudtrail",
    "jira",
    "slack",
    "duo",
    "cortex",
    "servicenow",
    "gcp",
    "proofpoint",
    "wiz",
    "git",
}


# --------------------------------------------------------------------------- #
# Catalog service
# --------------------------------------------------------------------------- #


def test_catalog_covers_expected_connectors() -> None:
    names = set(connector_catalog.get_catalog())
    assert EXPECTED.issubset(names)


def test_catalog_includes_mcp_connectors() -> None:
    """The agents-side MCP connectors are unioned into the catalog (#100)."""
    names = set(connector_catalog.get_catalog())
    assert EXPECTED_MCP_ONLY.issubset(names)


def test_catalog_engine_wins_on_name_clash() -> None:
    """Overlapping names (e.g. crowdstrike) keep the engine manifest.

    The engine crowdstrike manifest carries the ``isolate_host`` HITL action;
    the MCP one does not, so this pins the merge precedence.
    """
    m = connector_catalog.get_manifest("crowdstrike")
    assert m is not None
    assert "isolate_host" in {a.id for a in m.actions}


def test_catalog_is_memoised() -> None:
    assert connector_catalog.get_catalog() is connector_catalog.get_catalog()


def test_get_manifest_lookup() -> None:
    m = connector_catalog.get_manifest("crowdstrike")
    assert m is not None and m.name == "crowdstrike"
    assert connector_catalog.get_manifest("nonexistent") is None


# --------------------------------------------------------------------------- #
# List endpoint
# --------------------------------------------------------------------------- #


async def test_list_connectors(client, analyst_token) -> None:
    resp = await client.get("/api/v1/connectors", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    names = {c["name"] for c in body["items"]}
    assert EXPECTED.issubset(names)
    assert body["total"] == len(body["items"])

    cs = next(c for c in body["items"] if c["name"] == "crowdstrike")
    assert cs["action_count"] >= 1  # isolate_host
    assert cs["has_hitl_actions"] is True
    assert "detection_finding" in cs["ocsf_emits"]

    # An MCP-only connector surfaces too (Okta, an identity connector).
    assert EXPECTED_MCP_ONLY.issubset(names)
    okta = next(c for c in body["items"] if c["name"] == "okta")
    assert okta["query_count"] >= 1
    assert "authentication" in okta["ocsf_emits"]


async def test_list_filters_by_emits(client, analyst_token) -> None:
    resp = await client.get(
        "/api/v1/connectors?emits=authentication", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200
    names = {c["name"] for c in resp.json()["items"]}
    # Sentinel declares authentication on its KQL query; VirusTotal does not.
    assert "sentinel" in names
    assert "virustotal" not in names


async def test_list_filters_by_has_actions(client, analyst_token) -> None:
    with_actions = await client.get(
        "/api/v1/connectors?has_actions=true", headers=auth_header(analyst_token)
    )
    names = {c["name"] for c in with_actions.json()["items"]}
    assert "crowdstrike" in names  # isolate_host
    assert "shodan" not in names  # query-only CTI

    without = await client.get(
        "/api/v1/connectors?has_actions=false", headers=auth_header(analyst_token)
    )
    names_wo = {c["name"] for c in without.json()["items"]}
    assert "shodan" in names_wo
    assert "crowdstrike" not in names_wo


async def test_invalid_emits_value_is_422(client, analyst_token) -> None:
    resp = await client.get(
        "/api/v1/connectors?emits=not_a_class", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Detail endpoint
# --------------------------------------------------------------------------- #


async def test_get_connector_detail(client, analyst_token) -> None:
    resp = await client.get("/api/v1/connectors/crowdstrike", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    manifest = resp.json()
    assert manifest["name"] == "crowdstrike"
    assert isinstance(manifest["queries"], list)
    action_ids = {a["id"] for a in manifest["actions"]}
    assert "isolate_host" in action_ids
    isolate = next(a for a in manifest["actions"] if a["id"] == "isolate_host")
    assert isolate["hitl_required"] is True


async def test_get_unknown_connector_404(client, analyst_token) -> None:
    resp = await client.get("/api/v1/connectors/nonexistent", headers=auth_header(analyst_token))
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# AuthZ
# --------------------------------------------------------------------------- #


async def test_list_requires_auth(client) -> None:
    resp = await client.get("/api/v1/connectors")
    assert resp.status_code == 401


async def test_detail_requires_auth(client) -> None:
    resp = await client.get("/api/v1/connectors/crowdstrike")
    assert resp.status_code == 401
