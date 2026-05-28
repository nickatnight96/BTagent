"""Manifest coverage across all built-in integration nodes (#100 Phase 4).

Asserts every INTEGRATION-category node in the registry now carries a
ConnectorManifest + a capability_id that resolves to a real capability,
and exercises the policy middleware against the retrofitted connectors
(incl. CrowdStrike's isolate_host action -> HITL gate).
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP
from btagent_shared.types.connector import ConnectorManifest

# Import the integration modules so their nodes register.
import btagent_engine.integrations  # noqa: F401
from btagent_engine import NodeContext
from btagent_engine.middleware import (
    CAPABILITY_ID_KEY,
    ConnectorPolicyMiddleware,
    PendingHITLApproval,
)
from btagent_engine.node import NodeCategory, NodeRegistry


def _integration_node_classes():
    return [
        cls for cls in NodeRegistry.all().values() if cls.meta.category == NodeCategory.INTEGRATION
    ]


def test_every_integration_node_has_a_manifest():
    missing = []
    for cls in _integration_node_classes():
        manifest = getattr(cls, "manifest", None)
        if not isinstance(manifest, ConnectorManifest):
            missing.append(cls.meta.id)
    assert missing == [], f"integration nodes without a manifest: {missing}"


def test_every_integration_node_capability_id_resolves():
    bad = []
    for cls in _integration_node_classes():
        manifest = getattr(cls, "manifest", None)
        cap_id = getattr(cls, "capability_id", None)
        if not isinstance(manifest, ConnectorManifest) or cap_id is None:
            continue
        if manifest.capability(cap_id) is None:
            bad.append((cls.meta.id, cap_id))
    assert bad == [], f"nodes whose capability_id doesn't resolve: {bad}"


def test_expected_connectors_all_present():
    names = {
        cls.manifest.name
        for cls in _integration_node_classes()
        if isinstance(getattr(cls, "manifest", None), ConnectorManifest)
    }
    assert {
        "splunk",
        "sentinel",
        "elastic",
        "crowdstrike",
        "shodan",
        "greynoise",
        "abuseipdb",
        "misp",
        "virustotal",
    }.issubset(names)


async def test_crowdstrike_isolate_host_triggers_hitl():
    from btagent_engine.integrations.crowdstrike import (
        CrowdStrikeIsolateHostInput,
        CrowdStrikeIsolateHostNode,
    )

    mw = ConnectorPolicyMiddleware(active_tlp=TLP.RED)  # on-prem EDR allowed at RED
    node = CrowdStrikeIsolateHostNode()
    with pytest.raises(PendingHITLApproval) as ei:
        await mw.before_run(node, CrowdStrikeIsolateHostInput(hostname="WS-1"), _ctx())
    assert ei.value.capability_id == "isolate_host"
    assert ei.value.connector_name == "crowdstrike"


async def test_splunk_search_runs_at_red_no_hitl():
    from btagent_engine.integrations.splunk import (
        SplunkSearchInput,
        SplunkSearchNode,
    )

    mw = ConnectorPolicyMiddleware(active_tlp=TLP.RED)
    ctx = _ctx()
    # On-prem SIEM declares tlp_egress=RED -> allowed at any classification,
    # and it's a query -> no HITL.
    await mw.before_run(SplunkSearchNode(), SplunkSearchInput(query="index=x"), ctx)
    assert ctx.metadata[CAPABILITY_ID_KEY] == "search"


async def test_greynoise_blocked_at_red_context():
    # Cloud CTI declares tlp_egress=AMBER -> must be refused at RED.
    from btagent_engine.integrations.greynoise import (
        GreyNoiseLookupIPInput,
        GreyNoiseLookupIPNode,
    )
    from btagent_engine.middleware import ConnectorPolicyViolation

    mw = ConnectorPolicyMiddleware(active_tlp=TLP.RED)
    with pytest.raises(ConnectorPolicyViolation):
        await mw.before_run(GreyNoiseLookupIPNode(), GreyNoiseLookupIPInput(ip="1.2.3.4"), _ctx())


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_cov", org_id="org_test")
