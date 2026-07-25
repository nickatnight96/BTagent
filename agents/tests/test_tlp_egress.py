"""Tests for centralised TLP egress enforcement.

Covers the four egress kinds wired through
:mod:`btagent_agents.hooks._tlp_egress`:

* ``stix_export``      - STIX 2.1 bundle generation
* ``knowledge_ingest`` - RAG knowledge-base ingestion
* ``mcp_return``       - MCP tool-call return envelopes
* ``event_emit``       - WebSocket / Redis broadcast

Plus a regression test confirming the existing LLM-call gate in
:class:`btagent_agents.hooks.classification_hook.ClassificationCallback`
still raises :class:`TLPViolation` when an unauthorised provider is used.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from btagent_shared.security import TLPViolation, assert_tlp_allows_egress
from btagent_shared.types.config import TLP, ModelProvider

from btagent_agents.hooks.classification_hook import ClassificationCallback
from btagent_agents.mcp.adapters import (
    ResilientMCPToolAdapter,
    _enforce_tlp_on_mcp_return,
    _strip_red_items,
)

# --------------------------------------------------------------------------- #
# Per-egress-kind block / pass tests
# --------------------------------------------------------------------------- #

EGRESS_KINDS = ("stix_export", "knowledge_ingest", "mcp_return", "event_emit")


@pytest.mark.parametrize("kind", EGRESS_KINDS)
def test_red_payload_blocked_on_every_egress_kind(kind: str) -> None:
    """A payload tagged TLP:RED must be blocked on every egress channel."""
    payload = {
        "value": "1.2.3.4",
        "tlp_level": "red",
        "context": "C2 server seen in restricted incident",
    }
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(payload, kind, classification_ctx=TLP.GREEN)


@pytest.mark.parametrize("kind", EGRESS_KINDS)
@pytest.mark.parametrize(
    "ctx",
    [TLP.WHITE, TLP.GREEN, TLP.AMBER, TLP.AMBER_STRICT],
    ids=["white", "green", "amber", "amber_strict"],
)
def test_non_red_payload_passes(kind: str, ctx: TLP) -> None:
    """AMBER_STRICT and below pass through the gate without raising."""
    payload = {"value": "8.8.8.8", "tlp_level": ctx.value}
    # Should not raise.
    assert_tlp_allows_egress(payload, kind, classification_ctx=ctx)


@pytest.mark.parametrize("kind", EGRESS_KINDS)
def test_red_classification_context_blocks_even_clean_payload(kind: str) -> None:
    """If the investigation itself is TLP:RED, no egress is permitted."""
    payload = {"value": "8.8.8.8", "tlp_level": "green"}
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(payload, kind, classification_ctx=TLP.RED)


def test_unknown_egress_kind_raises_value_error() -> None:
    """Unknown egress kind names must be rejected -- no silent allow-list bypass."""
    with pytest.raises(ValueError, match="Unknown egress_kind"):
        assert_tlp_allows_egress({"x": 1}, "exfil_via_dns", classification_ctx=TLP.GREEN)


def test_violation_is_not_silently_swallowed() -> None:
    """Confirm :class:`TLPViolation` propagates up -- not caught internally."""

    def caller() -> None:
        assert_tlp_allows_egress(
            {"tlp_level": "red"},
            "mcp_return",
            classification_ctx=TLP.GREEN,
        )

    with pytest.raises(TLPViolation) as exc_info:
        caller()

    assert exc_info.value.tlp == TLP.RED
    assert "mcp_return" in str(exc_info.value)


# --------------------------------------------------------------------------- #
# Nested-payload detection
# --------------------------------------------------------------------------- #


def test_red_tag_in_nested_list_blocks() -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {"id": "indicator--1", "tlp_level": "green"},
            {"id": "indicator--2", "tlp_level": "red"},  # RED hidden inside list
        ],
    }
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(bundle, "stix_export", classification_ctx=TLP.GREEN)


def test_red_tag_in_nested_metadata_blocks() -> None:
    payload = {
        "title": "Incident report",
        "metadata": {
            "case": "INC-42",
            "tlp": "red",
        },
    }
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(payload, "knowledge_ingest", classification_ctx=TLP.AMBER)


# --------------------------------------------------------------------------- #
# Fail-closed classification resolution (GH #379)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_ctx",
    ["purple", "top-secret", "gren", "", "   ", "red\x00green"],
    ids=["garbage", "typo-level", "typo-green", "empty", "whitespace", "nul-injection"],
)
def test_unknown_classification_string_fails_closed_to_red(bad_ctx: str) -> None:
    """A supplied-but-unrecognised classification string must block egress.

    Regression for GH #379: the egress gate previously downgraded an
    unrecognised classification to TLP:GREEN (allowed), while the LLM-routing
    side fails closed to TLP:RED. That asymmetry let a malformed/garbage
    classification context permit egress it should block. The gate must now
    fail CLOSED, matching the routing side.
    """
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(
            {"value": "8.8.8.8"},
            "mcp_return",
            classification_ctx=bad_ctx,
        )


@pytest.mark.parametrize(
    "good_ctx",
    ["green", "white", "GREEN", "White", "amber", "amber_strict"],
    ids=["green", "white", "green-upper", "white-mixed", "amber", "amber_strict"],
)
def test_known_non_red_classification_string_still_egresses(good_ctx: str) -> None:
    """Known non-RED classification strings must keep egressing (no over-block)."""
    # Should not raise.
    assert_tlp_allows_egress(
        {"value": "8.8.8.8"},
        "mcp_return",
        classification_ctx=good_ctx,
    )


def test_none_classification_still_defaults_to_green() -> None:
    """An *absent* classification (None) stays GREEN -- unset != malformed."""
    # Should not raise: None is the documented AgentConfig default.
    assert_tlp_allows_egress({"value": "8.8.8.8"}, "mcp_return", classification_ctx=None)


def test_dict_with_uncoercible_tlp_field_fails_closed() -> None:
    """A mapping whose TLP field holds garbage fails CLOSED to RED."""
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(
            {"value": "8.8.8.8"},
            "mcp_return",
            classification_ctx={"tlp_level": "not-a-level"},
        )


def test_dict_without_tlp_field_defaults_to_green() -> None:
    """A mapping with no TLP field is 'unset' -> GREEN, not fail-closed."""
    # Should not raise.
    assert_tlp_allows_egress(
        {"value": "8.8.8.8"},
        "mcp_return",
        classification_ctx={"case": "INC-1", "owner": "alice"},
    )


# --------------------------------------------------------------------------- #
# Deep-nesting scan (GH #379): depth cap must not certify unscanned data safe
# --------------------------------------------------------------------------- #


def _nest(inner: Any, levels: int) -> dict[str, Any]:
    """Wrap *inner* in *levels* nested ``{"child": ...}`` dicts."""
    node: Any = inner
    for _ in range(levels):
        node = {"child": node}
    return node


def test_red_tag_nested_beyond_old_depth_cap_is_detected() -> None:
    """A ``tlp:red`` tag nested >8 levels deep must still be detected/blocked.

    Regression for GH #379: the scan hard-capped at depth 8 and returned
    ``False`` (i.e. 'no RED found') beyond it, so a RED tag hidden below the
    horizon slipped through defense-in-depth. The clean classification context
    means the block can only come from the recursive payload scan.
    """
    payload = _nest({"tlp_level": "red", "value": "1.2.3.4"}, levels=15)
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(payload, "stix_export", classification_ctx=TLP.GREEN)


def test_payload_too_deep_to_fully_scan_fails_closed() -> None:
    """A payload nested past the scan cap cannot be certified safe -> blocked.

    Even with no RED tag present, exceeding the depth cap means we cannot
    fully scan the branch, so the gate fails CLOSED rather than certifying
    unscanned data as egress-safe.
    """
    payload = _nest({"value": "benign-but-buried"}, levels=80)
    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress(payload, "stix_export", classification_ctx=TLP.GREEN)


# --------------------------------------------------------------------------- #
# MCP return path
# --------------------------------------------------------------------------- #


def test_mcp_return_strips_red_list_items() -> None:
    """Items inside a list tagged RED are stripped, not silently dropped wholesale."""
    result = {
        "status": "success",
        "events": [
            {"event_id": "1", "tlp_level": "green", "src_ip": "10.0.0.1"},
            {"event_id": "2", "tlp_level": "red", "src_ip": "10.0.0.2"},
            {"event_id": "3", "tlp_level": "amber", "src_ip": "10.0.0.3"},
        ],
    }
    cleaned, stripped = _strip_red_items(result)
    assert stripped == 1
    assert len(cleaned["events"]) == 2
    event_ids = [e["event_id"] for e in cleaned["events"]]
    assert "2" not in event_ids


def test_mcp_return_envelope_red_raises() -> None:
    """If the entire MCP envelope is RED, the wrapper raises."""
    envelope = {"status": "success", "tlp_level": "red", "data": [1, 2, 3]}
    with pytest.raises(TLPViolation):
        _enforce_tlp_on_mcp_return(
            envelope,
            server_name="splunk",
            tool_name="splunk_search",
            investigation_tlp="green",
        )


def test_mcp_return_clean_passes_through() -> None:
    envelope = {"status": "success", "events": [{"id": 1}]}
    out = _enforce_tlp_on_mcp_return(
        envelope,
        server_name="splunk",
        tool_name="splunk_search",
        investigation_tlp="green",
    )
    assert out == envelope


def test_mcp_return_strip_count_recorded() -> None:
    envelope = {
        "status": "success",
        "events": [
            {"id": 1, "tlp_level": "green"},
            {"id": 2, "tlp_level": "red"},
        ],
    }
    out = _enforce_tlp_on_mcp_return(
        envelope,
        server_name="splunk",
        tool_name="splunk_search",
        investigation_tlp="amber",
    )
    assert out["_tlp_stripped_count"] == 1
    assert len(out["events"]) == 1


@pytest.mark.asyncio
async def test_resilient_adapter_blocks_red_envelope() -> None:
    """End-to-end: ResilientMCPToolAdapter raises when MCP returns a RED envelope."""

    async def fake_tool(**_: Any) -> dict[str, Any]:
        return {"status": "success", "tlp_level": "red", "data": "secret"}

    adapter = ResilientMCPToolAdapter(
        server_name="virustotal",
        max_retries=1,
        investigation_tlp="green",
    )
    with pytest.raises(TLPViolation):
        await adapter.execute(fake_tool, tool_name="vt_lookup", arguments={})


# --------------------------------------------------------------------------- #
# Regression: existing LLM-call gate still works
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_classification_hook_llm_gate_still_blocks_unauthorised_provider() -> None:
    """The existing TLP:RED -> non-local-provider block must still fire."""
    fake_emitter = AsyncMock()
    fake_emitter.emit = AsyncMock()

    cb = ClassificationCallback(
        emitter=fake_emitter,
        tlp_level=TLP.RED,
        provider=ModelProvider.ANTHROPIC,
        investigation_id="inv_test_red",
    )

    with pytest.raises(TLPViolation) as exc_info:
        await cb.on_chat_model_start(
            serialized={"name": "claude-sonnet-4"},
            messages=[],
            run_id=uuid4(),
        )

    assert exc_info.value.tlp == TLP.RED
    assert exc_info.value.provider == ModelProvider.ANTHROPIC
    fake_emitter.emit.assert_awaited()


@pytest.mark.asyncio
async def test_classification_hook_llm_gate_allows_local_provider_for_red() -> None:
    """Sanity: TLP:RED is permitted on local providers (Ollama)."""
    fake_emitter = AsyncMock()
    fake_emitter.emit = AsyncMock()

    cb = ClassificationCallback(
        emitter=fake_emitter,
        tlp_level=TLP.RED,
        provider=ModelProvider.OLLAMA,
        investigation_id="inv_test_red_local",
    )

    # Should not raise.
    await cb.on_chat_model_start(
        serialized={"name": "llama3"},
        messages=[],
        run_id=uuid4(),
    )
    fake_emitter.emit.assert_not_awaited()


# --------------------------------------------------------------------------- #
# EventEmitter integration
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_event_emitter_drops_red_payload() -> None:
    """EventEmitterCallback must drop emit calls when classification is TLP:RED."""
    from btagent_agents.hooks.event_emitter_hook import EventEmitterCallback

    fake_emitter = AsyncMock()
    fake_emitter.emit = AsyncMock()

    cb = EventEmitterCallback(
        emitter=fake_emitter,
        investigation_id="inv_test_red_event",
        tlp_level=TLP.RED,
    )

    await cb.on_tool_end(
        output="sensitive payload",
        run_id=uuid4(),
    )

    # Drop = no emit happened.
    fake_emitter.emit.assert_not_awaited()


@pytest.mark.asyncio
async def test_event_emitter_passes_non_red_payload() -> None:
    from btagent_agents.hooks.event_emitter_hook import EventEmitterCallback

    fake_emitter = AsyncMock()
    fake_emitter.emit = AsyncMock()

    cb = EventEmitterCallback(
        emitter=fake_emitter,
        investigation_id="inv_test_amber_event",
        tlp_level=TLP.AMBER,
    )

    await cb.on_tool_end(
        output="benign payload",
        run_id=uuid4(),
    )

    fake_emitter.emit.assert_awaited_once()
