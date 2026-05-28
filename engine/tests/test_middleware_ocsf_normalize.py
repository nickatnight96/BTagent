"""Tests for OCSFNormalizerMiddleware (#100 Layer 2)."""

from __future__ import annotations

from typing import ClassVar

import pytest
from btagent_shared.types.connector import (
    ConnectorManifest,
    CredentialType,
    OCSFEventClass,
    QueryCapability,
    TransportKind,
)
from pydantic import BaseModel

from btagent_engine import NodeContext
from btagent_engine.middleware import (
    CAPABILITY_ID_KEY,
    OCSF_SUMMARY_KEY,
    OCSFContractViolation,
    OCSFNormalizerMiddleware,
)
from btagent_engine.node import Node, NodeCategory, NodeMeta

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


_AUTH_MANIFEST = ConnectorManifest(
    name="okta_like",
    version="0.1.0",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.OAUTH2,
    queries=[
        QueryCapability(
            id="audit_log",
            ocsf_emits=[
                OCSFEventClass.AUTHENTICATION,
                OCSFEventClass.AUDIT_ACTIVITY,
            ],
        ),
        QueryCapability(
            id="raw_dump",
            ocsf_emits=[],  # declares no OCSF -> validation skipped
        ),
    ],
)


class _StubInput(BaseModel):
    pass


class _AuditOutput(BaseModel):
    events: list[dict] = []
    ocsf_event_class: str | None = None
    ocsf_emits: list[str] = []


class _AuditNode(Node[_StubInput, _AuditOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="integration.okta_like.audit_log",
        name="Audit Log",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    input_schema: ClassVar[type[BaseModel]] = _StubInput
    output_schema: ClassVar[type[BaseModel]] = _AuditOutput
    manifest: ClassVar[ConnectorManifest] = _AUTH_MANIFEST
    capability_id: ClassVar[str] = "audit_log"

    async def run(self, input, ctx):
        return _AuditOutput()


class _RawDumpNode(_AuditNode):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="integration.okta_like.raw_dump",
        name="Raw Dump",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    capability_id: ClassVar[str] = "raw_dump"


def _ctx_with_capability(capability_id: str) -> NodeContext:
    ctx = NodeContext(run_id="r_ocsf", org_id="org_test")
    ctx.metadata[CAPABILITY_ID_KEY] = capability_id
    return ctx


# --------------------------------------------------------------------------- #
# Happy paths
# --------------------------------------------------------------------------- #


async def test_output_with_declared_class_passes():
    mw = OCSFNormalizerMiddleware()
    node = _AuditNode()
    output = _AuditOutput(ocsf_event_class="authentication")
    ctx = _ctx_with_capability("audit_log")
    await mw.after_run(node, _StubInput(), output, ctx)
    summary = ctx.metadata[OCSF_SUMMARY_KEY]
    assert summary["observed"] == ["authentication"]
    assert summary["undeclared_seen"] == []


async def test_per_event_class_extraction_passes():
    mw = OCSFNormalizerMiddleware()
    node = _AuditNode()
    output = _AuditOutput(
        events=[
            {"class": "authentication", "user": "alice"},
            {"class": "audit_activity", "user": "bob"},
        ]
    )
    ctx = _ctx_with_capability("audit_log")
    await mw.after_run(node, _StubInput(), output, ctx)
    summary = ctx.metadata[OCSF_SUMMARY_KEY]
    assert set(summary["observed"]) == {"authentication", "audit_activity"}


async def test_capability_declaring_no_ocsf_skips_validation():
    """A capability with ocsf_emits=[] permits any output shape."""
    mw = OCSFNormalizerMiddleware()
    node = _RawDumpNode()
    output = _AuditOutput(ocsf_event_class="network_activity")  # would violate audit_log
    ctx = _ctx_with_capability("raw_dump")
    await mw.after_run(node, _StubInput(), output, ctx)
    # No summary written (we skip validation entirely when declared==[]).
    assert OCSF_SUMMARY_KEY not in ctx.metadata


async def test_output_without_ocsf_claims_is_silent():
    mw = OCSFNormalizerMiddleware()
    node = _AuditNode()
    output = _AuditOutput()  # no OCSF claims at all
    ctx = _ctx_with_capability("audit_log")
    await mw.after_run(node, _StubInput(), output, ctx)
    summary = ctx.metadata[OCSF_SUMMARY_KEY]
    assert summary["observed"] == []
    assert summary["undeclared_seen"] == []


# --------------------------------------------------------------------------- #
# Contract violations
# --------------------------------------------------------------------------- #


async def test_undeclared_top_level_class_raises():
    mw = OCSFNormalizerMiddleware()
    node = _AuditNode()
    output = _AuditOutput(ocsf_event_class="network_activity")
    ctx = _ctx_with_capability("audit_log")
    with pytest.raises(OCSFContractViolation):
        await mw.after_run(node, _StubInput(), output, ctx)


async def test_per_event_undeclared_class_raises():
    mw = OCSFNormalizerMiddleware()
    node = _AuditNode()
    output = _AuditOutput(events=[{"class": "process_activity", "user": "alice"}])
    ctx = _ctx_with_capability("audit_log")
    with pytest.raises(OCSFContractViolation):
        await mw.after_run(node, _StubInput(), output, ctx)


async def test_unknown_class_string_raises():
    mw = OCSFNormalizerMiddleware()
    node = _AuditNode()
    output = _AuditOutput(ocsf_event_class="totally_made_up_class")
    ctx = _ctx_with_capability("audit_log")
    with pytest.raises(OCSFContractViolation):
        await mw.after_run(node, _StubInput(), output, ctx)


# --------------------------------------------------------------------------- #
# Edge: no manifest, or no capability id in context
# --------------------------------------------------------------------------- #


class _NoManifestNode(Node[_StubInput, _AuditOutput]):
    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.nomanifest_ocsf",
        name="No Manifest",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema: ClassVar[type[BaseModel]] = _StubInput
    output_schema: ClassVar[type[BaseModel]] = _AuditOutput

    async def run(self, input, ctx):
        return _AuditOutput()


async def test_node_without_manifest_is_a_noop():
    mw = OCSFNormalizerMiddleware()
    ctx = NodeContext(run_id="r_x", org_id="org_test")
    await mw.after_run(
        _NoManifestNode(),
        _StubInput(),
        _AuditOutput(ocsf_event_class="anything"),
        ctx,
    )
    assert OCSF_SUMMARY_KEY not in ctx.metadata


async def test_missing_capability_id_in_context_is_a_noop():
    mw = OCSFNormalizerMiddleware()
    ctx = NodeContext(run_id="r_x", org_id="org_test")  # no capability id
    await mw.after_run(
        _AuditNode(),
        _StubInput(),
        _AuditOutput(ocsf_event_class="network_activity"),
        ctx,
    )
    assert OCSF_SUMMARY_KEY not in ctx.metadata
