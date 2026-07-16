"""Manifest coverage for the agents-side MCP server registry (#100 Layer 3).

The engine's Phase-4 suite pins manifests for its integration nodes; this
suite is the same contract for ``discovery._SERVER_CLASSES``:

- every registered server has a manifest, keyed by its ``server_id``
- **drift lock**: manifest capability ids == the server's
  ``get_tool_metadata()`` names, as equal sets in both directions — a
  connector growing (or renaming) a tool without declaring its policy
  fails here
- policy invariants: containment actions and the PR composer stay
  HITL-gated; collaboration sinks are declared actions (never queries);
  on-prem telemetry keeps TLP.RED, org-tenant clouds AMBER_STRICT
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP
from btagent_shared.types.connector import ActionCapability, ConnectorManifest

from btagent_agents.mcp import discovery
from btagent_agents.mcp.manifests import MANIFESTS, get_manifest


def _servers() -> dict[str, type]:
    discovery._ensure_servers_loaded()
    return dict(discovery._SERVER_CLASSES)


def _instantiate(cls: type):
    try:
        return cls(mock_mode=True)
    except TypeError:
        return cls()


def _tool_names(cls: type) -> set[str]:
    return {m["name"] for m in _instantiate(cls).get_tool_metadata()}


def _capability_ids(manifest: ConnectorManifest) -> set[str]:
    return {c.id for c in (*manifest.queries, *manifest.actions, *manifest.streams)}


# --------------------------------------------------------------------------- #
# Coverage + drift lock
# --------------------------------------------------------------------------- #


def test_every_registered_server_has_a_manifest() -> None:
    missing = [sid for sid in _servers() if sid not in MANIFESTS]
    assert missing == [], f"MCP servers without a manifest: {missing}"


def test_no_orphan_manifests() -> None:
    orphans = [name for name in MANIFESTS if name not in _servers()]
    assert orphans == [], f"manifests without a registered server: {orphans}"


def test_manifest_name_matches_server_id() -> None:
    mismatched = [sid for sid, m in MANIFESTS.items() if m.name != sid]
    assert mismatched == []


@pytest.mark.parametrize("server_id", sorted(discovery._SERVER_CLASSES or _servers()))
def test_capability_ids_match_tool_names_exactly(server_id: str) -> None:
    """The drift lock: tools and declared capabilities are the same set."""
    cls = _servers()[server_id]
    tools = _tool_names(cls)
    caps = _capability_ids(MANIFESTS[server_id])
    assert caps == tools, (
        f"{server_id}: undeclared tools {sorted(tools - caps)}; "
        f"stale capabilities {sorted(caps - tools)}"
    )


def test_capability_lookup_helper_resolves() -> None:
    manifest = get_manifest("defender_endpoint")
    assert manifest is not None
    cap = manifest.capability("mde_isolate_machine")
    assert isinstance(cap, ActionCapability)
    assert get_manifest("nonexistent") is None


# --------------------------------------------------------------------------- #
# Policy invariants
# --------------------------------------------------------------------------- #

CONTAINMENT_ACTIONS = {
    ("crowdstrike", "cs_isolate_host"),
    ("defender_endpoint", "mde_isolate_machine"),
    ("sentinelone", "s1_mitigate_threat"),
}

SINK_ACTIONS = {
    ("jira", "jira_create_incident"),
    ("jira", "jira_add_comment"),
    ("jira", "jira_transition_issue"),
    ("slack", "slack_create_incident_channel"),
    ("slack", "slack_post_message"),
    ("slack", "slack_pin_message"),
    ("git", "git_open_detection_pr"),
}


def test_containment_actions_are_hitl_gated() -> None:
    for server_id, cap_id in CONTAINMENT_ACTIONS:
        cap = MANIFESTS[server_id].capability(cap_id)
        assert isinstance(cap, ActionCapability), (server_id, cap_id)
        assert cap.hitl_required is True, (server_id, cap_id)
        assert cap.blast_radius.value == "single_host", (server_id, cap_id)


def test_git_pr_composer_stays_hitl_gated() -> None:
    cap = MANIFESTS["git"].capability("git_open_detection_pr")
    assert isinstance(cap, ActionCapability)
    assert cap.hitl_required is True


def test_mutating_tools_are_declared_as_actions_not_queries() -> None:
    for server_id, cap_id in CONTAINMENT_ACTIONS | SINK_ACTIONS:
        manifest = MANIFESTS[server_id]
        query_ids = {q.id for q in manifest.queries}
        assert cap_id not in query_ids, f"{server_id}.{cap_id} declared as a query"
        assert isinstance(manifest.capability(cap_id), ActionCapability)


def test_tlp_egress_tiers() -> None:
    """On-prem telemetry stays RED; org-tenant clouds stay AMBER_STRICT."""
    on_prem = {"splunk", "sentinel", "elastic", "crowdstrike", "zeek"}
    for name, manifest in MANIFESTS.items():
        expected = TLP.RED if name in on_prem else TLP.AMBER_STRICT
        for cap in (*manifest.queries, *manifest.actions, *manifest.streams):
            assert cap.tlp_egress == expected, (name, cap.id, cap.tlp_egress)


def test_queries_never_require_hitl() -> None:
    for name, manifest in MANIFESTS.items():
        for q in manifest.queries:
            assert q.hitl_required is False, (name, q.id)
