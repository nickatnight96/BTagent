"""Tests for ConnectorPolicyMiddleware (#100 Layer 3)."""

from __future__ import annotations

from typing import ClassVar

import pytest
from btagent_shared.types.config import TLP
from btagent_shared.types.connector import (
    ActionCapability,
    ConnectorManifest,
    CostClass,
    CredentialType,
    QueryCapability,
    TransportKind,
)
from pydantic import BaseModel

from btagent_engine import NodeContext
from btagent_engine.middleware import (
    CAPABILITY_ID_KEY,
    COST_CLASS_KEY,
    MANIFEST_NAME_KEY,
    ConnectorPolicyMiddleware,
    ConnectorPolicyViolation,
    PendingHITLApproval,
)
from btagent_engine.node import Node, NodeCategory, NodeMeta

# --------------------------------------------------------------------------- #
# Test fixtures: a manifest + a node that points at one of its capabilities
# --------------------------------------------------------------------------- #


_TEST_MANIFEST = ConnectorManifest(
    name="testconn",
    version="0.1.0",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="ping",
            tlp_egress=TLP.GREEN,
            cost_class=CostClass.CHEAP,
            hitl_required=False,
        ),
        QueryCapability(
            id="sensitive_dump",
            tlp_egress=TLP.GREEN,  # capability only allowed at GREEN-or-lower
            cost_class=CostClass.EXPENSIVE,
            hitl_required=False,
        ),
    ],
    actions=[
        ActionCapability(
            id="purge_data",
            tlp_egress=TLP.GREEN,
            cost_class=CostClass.EXPENSIVE,
            # hitl_required defaults to True for ActionCapability
        ),
    ],
)


class _StubInput(BaseModel):
    capability_id_override: str | None = None  # rename to avoid pydantic underscore rules


class _StubOutput(BaseModel):
    ok: bool = True


class _PingNode(Node[_StubInput, _StubOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="integration.testconn.ping",
        name="Test Ping",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    input_schema: ClassVar[type[BaseModel]] = _StubInput
    output_schema: ClassVar[type[BaseModel]] = _StubOutput
    manifest: ClassVar[ConnectorManifest] = _TEST_MANIFEST
    capability_id: ClassVar[str] = "ping"

    async def run(self, input, ctx):
        return _StubOutput(ok=True)


class _PurgeNode(_PingNode):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="integration.testconn.purge",
        name="Test Purge",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    capability_id: ClassVar[str] = "purge_data"


class _SensitiveNode(_PingNode):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="integration.testconn.sensitive",
        name="Test Sensitive",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    capability_id: ClassVar[str] = "sensitive_dump"


class _NoManifestNode(Node[_StubInput, _StubOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.nomanifest",
        name="No Manifest",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema: ClassVar[type[BaseModel]] = _StubInput
    output_schema: ClassVar[type[BaseModel]] = _StubOutput

    async def run(self, input, ctx):
        return _StubOutput(ok=True)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_policy", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy paths
# --------------------------------------------------------------------------- #


async def test_query_capability_runs_without_hitl_and_records_cost():
    mw = ConnectorPolicyMiddleware()
    ctx = _ctx()
    await mw.before_run(_PingNode(), _StubInput(), ctx)
    assert ctx.metadata[MANIFEST_NAME_KEY] == "testconn"
    assert ctx.metadata[CAPABILITY_ID_KEY] == "ping"
    assert ctx.metadata[COST_CLASS_KEY] == "cheap"


async def test_no_manifest_is_a_noop():
    mw = ConnectorPolicyMiddleware()
    ctx = _ctx()
    await mw.before_run(_NoManifestNode(), _StubInput(), ctx)
    assert CAPABILITY_ID_KEY not in ctx.metadata
    assert COST_CLASS_KEY not in ctx.metadata


# --------------------------------------------------------------------------- #
# HITL gate
# --------------------------------------------------------------------------- #


async def test_action_capability_pauses_with_pending_hitl():
    mw = ConnectorPolicyMiddleware()
    with pytest.raises(PendingHITLApproval) as ei:
        await mw.before_run(_PurgeNode(), _StubInput(), _ctx())
    assert ei.value.capability_id == "purge_data"
    assert ei.value.connector_name == "testconn"


# --------------------------------------------------------------------------- #
# TLP egress check
# --------------------------------------------------------------------------- #


async def test_tlp_red_context_refuses_green_capability():
    mw = ConnectorPolicyMiddleware(active_tlp=TLP.RED)
    with pytest.raises(ConnectorPolicyViolation):
        await mw.before_run(_PingNode(), _StubInput(), _ctx())


async def test_tlp_green_context_allows_green_capability():
    mw = ConnectorPolicyMiddleware(active_tlp=TLP.GREEN)
    ctx = _ctx()
    await mw.before_run(_PingNode(), _StubInput(), ctx)
    assert ctx.metadata[CAPABILITY_ID_KEY] == "ping"


async def test_tlp_white_context_allows_amber_capability():
    # Build a manifest with an amber-egress capability so we exercise the
    # ordering check in both directions.
    amber_manifest = ConnectorManifest(
        name="amber",
        version="0.1.0",
        transport=TransportKind.HTTP_REST,
        auth=CredentialType.API_KEY,
        queries=[QueryCapability(id="lookup", tlp_egress=TLP.AMBER, hitl_required=False)],
    )

    class _AmberNode(_PingNode):
        meta: ClassVar[NodeMeta] = NodeMeta(
            id="integration.amber.lookup",
            name="Amber Lookup",
            version="0.1.0",
            category=NodeCategory.INTEGRATION,
        )
        manifest: ClassVar[ConnectorManifest] = amber_manifest
        capability_id: ClassVar[str] = "lookup"

    mw = ConnectorPolicyMiddleware(active_tlp=TLP.WHITE)
    await mw.before_run(_AmberNode(), _StubInput(), _ctx())  # no raise == pass


# --------------------------------------------------------------------------- #
# Capability resolution
# --------------------------------------------------------------------------- #


async def test_unknown_capability_raises_violation():
    class _BogusNode(_PingNode):
        meta: ClassVar[NodeMeta] = NodeMeta(
            id="integration.testconn.bogus",
            name="Bogus",
            version="0.1.0",
            category=NodeCategory.INTEGRATION,
        )
        capability_id: ClassVar[str] = "does_not_exist"

    mw = ConnectorPolicyMiddleware()
    with pytest.raises(ConnectorPolicyViolation):
        await mw.before_run(_BogusNode(), _StubInput(), _ctx())
