"""Tests for KnowledgeUpsertNode + the FakeKnowledgeClient round-trip.

The Node is a thin pass-through to the injected client; tests assert
that title / content / source_type / metadata / classification all
survive the round-trip unchanged. The TLP gate is the BACKEND's job
(see module docstring); here we only verify the Node propagates the
classification value -- it does not raise on TLP:RED.
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.knowledge import (
    FakeKnowledgeClient,
    KnowledgeUpsertInput,
    KnowledgeUpsertNode,
    KnowledgeUpsertOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(
        run_id="r_knowledge_upsert",
        org_id="org_default",
        investigation_id="inv_test",
    )


# ---------------------------------------------------------------------------
# Direct Node.run tests (constructor-injected client)
# ---------------------------------------------------------------------------


async def test_upsert_round_trips_title_content_metadata_to_client():
    """Every field on the input model must reach the client unchanged so
    the backend stores exactly what the workflow author specified."""
    fake = FakeKnowledgeClient()
    node = KnowledgeUpsertNode(client=fake)

    out = await node.run(
        KnowledgeUpsertInput(
            title="APT29 IOC Bundle",
            content="hash: abc123\ndomain: evil.example",
            source_type="cti_report",
            metadata={"author": "analyst-1", "tlp": "amber"},
        ),
        _ctx(),
    )
    assert isinstance(out, KnowledgeUpsertOutput)
    assert out.document_id.startswith("doc_fake_")
    assert out.chunks >= 1

    assert len(fake.upsert_calls) == 1
    call = fake.upsert_calls[0]
    assert call["title"] == "APT29 IOC Bundle"
    assert call["content"] == "hash: abc123\ndomain: evil.example"
    assert call["source_type"] == "cti_report"
    assert call["metadata"] == {"author": "analyst-1", "tlp": "amber"}


async def test_upsert_passes_classification_through_to_client():
    """Classification must be propagated verbatim. The backend's TLP gate
    decides what to do with it; the Node is a transport layer here."""
    fake = FakeKnowledgeClient()
    node = KnowledgeUpsertNode(client=fake)

    await node.run(
        KnowledgeUpsertInput(
            title="Internal runbook",
            content="step 1: contain. step 2: eradicate.",
            source_type="runbook",
            classification="amber_strict",
        ),
        _ctx(),
    )
    assert fake.upsert_calls[-1]["classification"] == "amber_strict"


async def test_upsert_red_classification_does_not_raise_in_engine():
    """TLP:RED enforcement is the BACKEND's responsibility -- the engine
    Node passes the value through and lets the backend gate fire. Single
    source of truth for the classification policy.

    The fake client records the classification but doesn't enforce a
    policy, so this call should succeed at the engine layer."""
    fake = FakeKnowledgeClient()
    node = KnowledgeUpsertNode(client=fake)

    out = await node.run(
        KnowledgeUpsertInput(
            title="Sensitive RED report",
            content="redacted",
            source_type="cti_report",
            classification="red",
        ),
        _ctx(),
    )
    # Engine returned a result (no engine-side raise); classification recorded.
    assert isinstance(out, KnowledgeUpsertOutput)
    assert fake.upsert_calls[-1]["classification"] == "red"


async def test_upsert_default_metadata_is_empty_dict_not_none():
    """The Pydantic ``default_factory=dict`` ensures the client receives a
    real dict; this guards against a regression where someone makes
    metadata optional and ``None`` slips through."""
    fake = FakeKnowledgeClient()
    node = KnowledgeUpsertNode(client=fake)

    await node.run(
        KnowledgeUpsertInput(
            title="No-metadata doc",
            content="body",
            source_type="runbook",
        ),
        _ctx(),
    )
    assert fake.upsert_calls[-1]["metadata"] == {}
    # And classification defaults to None (not the string "None").
    assert fake.upsert_calls[-1]["classification"] is None


# ---------------------------------------------------------------------------
# End-to-end via Runner (validates middleware pipeline + dict payload path)
# ---------------------------------------------------------------------------


async def test_upsert_end_to_end_through_runner_with_fake_client():
    """The Runner validates dict payloads against input_schema, runs the
    middleware chain, and adapts the output -- exercise the full path."""
    fake = FakeKnowledgeClient()
    node = KnowledgeUpsertNode(client=fake)

    out = await Runner().execute(
        node,
        {
            "title": "Lessons learned: incident 42",
            "content": "Detection lagged because the rule was scoped too narrowly.",
            "source_type": "postmortem",
            "metadata": {"incident_id": "inc_42"},
        },
        _ctx(),
    )
    assert isinstance(out, KnowledgeUpsertOutput)
    assert out.document_id.startswith("doc_fake_")
    assert out.chunks >= 1
    assert fake.upsert_calls[-1]["metadata"] == {"incident_id": "inc_42"}


# ---------------------------------------------------------------------------
# Registry registration
# ---------------------------------------------------------------------------


def test_upsert_node_is_registered():
    """The @NodeRegistry.register decorator must publish the Node under its
    stable id so the workflow compiler can resolve it from a YAML reference."""
    assert NodeRegistry.get("knowledge.upsert") is KnowledgeUpsertNode


def test_upsert_node_falls_back_to_factory_when_no_client_given():
    """No-arg constructor must yield a working client (the executor calls
    ``node_cls()``); the default factory is FakeKnowledgeClient so the
    no-arg path is safe-by-default."""
    node = KnowledgeUpsertNode()  # No client argument.
    assert isinstance(node._client, FakeKnowledgeClient)
