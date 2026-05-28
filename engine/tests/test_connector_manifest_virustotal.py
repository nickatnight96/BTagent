"""End-to-end manifest test for the retrofitted VirusTotal connector (#100).

Proves the pattern: a single ConnectorManifest is attached to all three
VT node classes; each node declares its capability_id; the policy
middleware routes correctly per node; the OCSF normalizer doesn't
choke on the existing mock output shape.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP
from btagent_shared.types.connector import OCSFEventClass

from btagent_engine import NodeContext
from btagent_engine.integrations.virustotal import (
    VIRUSTOTAL_MANIFEST,
    VirusTotalDomainLookupInput,
    VirusTotalDomainLookupNode,
    VirusTotalHashLookupInput,
    VirusTotalHashLookupNode,
    VirusTotalIPLookupInput,
    VirusTotalIPLookupNode,
)
from btagent_engine.middleware import (
    CAPABILITY_ID_KEY,
    COST_CLASS_KEY,
    MANIFEST_NAME_KEY,
    ConnectorPolicyMiddleware,
    OCSFNormalizerMiddleware,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_vt", org_id="org_test")


# --------------------------------------------------------------------------- #
# Manifest shape
# --------------------------------------------------------------------------- #


def test_manifest_declares_three_lookup_capabilities():
    ids = {c.id for c in VIRUSTOTAL_MANIFEST.queries}
    assert ids == {"ip_lookup", "domain_lookup", "hash_lookup"}
    assert VIRUSTOTAL_MANIFEST.actions == []
    assert VIRUSTOTAL_MANIFEST.streams == []


def test_all_capabilities_emit_threat_intelligence():
    for cap in VIRUSTOTAL_MANIFEST.queries:
        assert OCSFEventClass.THREAT_INTELLIGENCE in cap.ocsf_emits


def test_each_node_class_points_at_correct_capability():
    assert VirusTotalIPLookupNode.capability_id == "ip_lookup"
    assert VirusTotalDomainLookupNode.capability_id == "domain_lookup"
    assert VirusTotalHashLookupNode.capability_id == "hash_lookup"


def test_capabilities_emitting_lookup_resolves_all_three():
    found = VIRUSTOTAL_MANIFEST.capabilities_emitting(OCSFEventClass.THREAT_INTELLIGENCE)
    assert {c.id for c in found} == {"ip_lookup", "domain_lookup", "hash_lookup"}


# --------------------------------------------------------------------------- #
# Policy middleware routes correctly per node
# --------------------------------------------------------------------------- #


async def test_policy_middleware_records_ip_lookup_capability(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    policy = ConnectorPolicyMiddleware(active_tlp=TLP.GREEN)
    ctx = _ctx()
    node = VirusTotalIPLookupNode()
    await policy.before_run(node, VirusTotalIPLookupInput(ip="8.8.8.8"), ctx)
    assert ctx.metadata[MANIFEST_NAME_KEY] == "virustotal"
    assert ctx.metadata[CAPABILITY_ID_KEY] == "ip_lookup"
    assert ctx.metadata[COST_CLASS_KEY] == "moderate"


async def test_policy_middleware_records_hash_lookup_capability(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    policy = ConnectorPolicyMiddleware(active_tlp=TLP.GREEN)
    ctx = _ctx()
    node = VirusTotalHashLookupNode()
    await policy.before_run(node, VirusTotalHashLookupInput(hash="a" * 64), ctx)
    assert ctx.metadata[CAPABILITY_ID_KEY] == "hash_lookup"


# --------------------------------------------------------------------------- #
# OCSF normalizer doesn't break on existing VT outputs
# --------------------------------------------------------------------------- #


async def test_ocsf_normalizer_silent_when_vt_output_has_no_claims(monkeypatch):
    """VT's existing mock output doesn't carry OCSF tags — that's allowed.

    The normalizer logs an empty observation rather than refusing; this
    confirms the retrofit is backwards-compatible with the connector's
    current output shape.
    """
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    # GREEN context: this test exercises the OCSF normalizer, not the TLP
    # gate (which now fails closed when no active_tlp is given).
    policy = ConnectorPolicyMiddleware(active_tlp=TLP.GREEN)
    norm = OCSFNormalizerMiddleware()
    ctx = _ctx()

    node = VirusTotalIPLookupNode()
    input = VirusTotalIPLookupInput(ip="185.220.101.42")
    await policy.before_run(node, input, ctx)
    output = await node.run(input, ctx)
    await norm.after_run(node, input, output, ctx)

    from btagent_engine.middleware import OCSF_SUMMARY_KEY

    summary = ctx.metadata[OCSF_SUMMARY_KEY]
    assert summary["connector"] == "virustotal"
    assert summary["capability"] == "ip_lookup"
    assert summary["declared"] == ["threat_intelligence"]
    assert summary["observed"] == []  # no claims in current output
    assert summary["undeclared_seen"] == []  # so no violation either
