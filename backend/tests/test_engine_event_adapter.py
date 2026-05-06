"""Coverage for ``btagent_backend.ws.engine_event_adapter``.

Verifies the engine -> legacy ``EventType`` translation table documented
in the module docstring. The adapter is the cutover seam between the
new ``EventEmitterMiddleware`` taxonomy (``node.start`` / ``node.end`` /
``node.error``) and the legacy browser consumers, so these tests are
intentionally exhaustive across the seven node categories and all three
lifecycle events.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.events import EventEnvelope, EventType

from btagent_backend.ws.engine_event_adapter import adapt_engine_event

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make(
    event_type: str,
    *,
    category: str,
    node_id: str = "test.node.id",
    node_name: str = "Test Node",
    investigation_id: str = "inv_01abc",
    run_id: str = "run_01xyz",
    **extra,
) -> dict:
    """Build an engine event dict in the shape the adapter consumes."""
    payload: dict = {
        "event_type": event_type,
        "investigation_id": investigation_id,
        "run_id": run_id,
        "node": {
            "id": node_id,
            "name": node_name,
            "category": category,
        },
    }
    payload.update(extra)
    return payload


# --------------------------------------------------------------------------- #
# Mapping table — happy paths
# --------------------------------------------------------------------------- #


def test_node_start_reasoning_maps_to_thinking_with_model_and_run_id():
    event = _make(
        "node.start",
        category="reasoning",
        node_id="reasoning.llm_call",
        node_name="claude-3-5-sonnet",
        run_id="run_01abc",
        model="anthropic/claude-3-5-sonnet",
        input={"prompt": "Investigate the alert"},
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.THINKING
    assert envelope.data["model"] == "anthropic/claude-3-5-sonnet"
    assert envelope.data["run_id"] == "run_01abc"
    assert envelope.data["node_id"] == "reasoning.llm_call"
    assert envelope.investigation_id.startswith("inv_")


def test_node_end_reasoning_maps_to_output_with_text():
    event = _make(
        "node.end",
        category="reasoning",
        node_id="reasoning.llm_call",
        output={"text": "The IP is malicious.", "tokens": 42},
        duration_ms=812.4,
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.OUTPUT
    assert envelope.data["text"] == "The IP is malicious."
    assert envelope.data["run_id"] == "run_01xyz"
    assert envelope.data["node_id"] == "reasoning.llm_call"


def test_node_start_integration_maps_to_tool_start_with_tool_name_and_input():
    event = _make(
        "node.start",
        category="integration",
        node_id="integration.greynoise.lookup_ip",
        node_name="GreyNoise Lookup",
        input={"ip": "8.8.8.8"},
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.TOOL_START
    assert envelope.data["tool_name"] == "GreyNoise Lookup"
    assert envelope.data["input"] == {"ip": "8.8.8.8"}
    assert envelope.data["node_id"] == "integration.greynoise.lookup_ip"


def test_node_end_integration_maps_to_tool_end_with_output_and_duration():
    event = _make(
        "node.end",
        category="integration",
        node_id="integration.greynoise.lookup_ip",
        output={"verdict": "benign", "classification": "good"},
        duration_ms=152.7,
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.TOOL_END
    assert envelope.data["output"] == {"verdict": "benign", "classification": "good"}
    assert envelope.data["duration_ms"] == 152.7
    assert envelope.data["node_id"] == "integration.greynoise.lookup_ip"


def test_node_end_integration_derives_duration_from_started_and_ended_at():
    """When ``duration_ms`` is absent, the adapter falls back to wall-clock."""
    event = _make(
        "node.end",
        category="integration",
        node_id="integration.virustotal.lookup_hash",
        output="hash known malicious",
        started_at=1_700_000_000.000,
        ended_at=1_700_000_000.250,
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.TOOL_END
    assert envelope.data["duration_ms"] == 250.0


# --------------------------------------------------------------------------- #
# node.error — source field by category
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "category, expected_source",
    [
        ("reasoning", "llm"),
        ("integration", "tool"),
        ("decision", "decision"),
        ("data", "data"),
        ("knowledge", "knowledge"),
    ],
)
def test_node_error_maps_to_error_with_source_from_category(category, expected_source):
    event = _make(
        "node.error",
        category=category,
        node_id=f"{category}.broken",
        error="connection refused",
        error_type="ConnectionError",
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.ERROR
    assert envelope.data["error"] == "connection refused"
    assert envelope.data["error_type"] == "ConnectionError"
    assert envelope.data["source"] == expected_source


# --------------------------------------------------------------------------- #
# Categories that don't have a legacy mapping
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("category", ["decision", "data", "output", "trigger", "knowledge"])
def test_non_legacy_category_start_returns_none(category):
    event = _make("node.start", category=category, node_id=f"{category}.example")
    assert adapt_engine_event(event) is None


@pytest.mark.parametrize("category", ["decision", "data", "output", "trigger", "knowledge"])
def test_non_legacy_category_end_returns_none(category):
    event = _make(
        "node.end",
        category=category,
        node_id=f"{category}.example",
        output={"ok": True},
    )
    assert adapt_engine_event(event) is None


# --------------------------------------------------------------------------- #
# Defensive paths
# --------------------------------------------------------------------------- #


def test_malformed_payload_missing_node_returns_none_and_warns(caplog):
    bad = {"event_type": "node.start", "run_id": "r1", "investigation_id": "inv_x"}
    with caplog.at_level(logging.WARNING, logger="btagent.ws.engine_event_adapter"):
        result = adapt_engine_event(bad)
    assert result is None
    assert any("'node' field" in rec.message for rec in caplog.records)


def test_malformed_payload_missing_category_returns_none_and_warns(caplog):
    bad = {
        "event_type": "node.start",
        "run_id": "r1",
        "investigation_id": "inv_x",
        "node": {"id": "x.y", "name": "Y"},  # no category
    }
    with caplog.at_level(logging.WARNING, logger="btagent.ws.engine_event_adapter"):
        result = adapt_engine_event(bad)
    assert result is None
    assert any("'node.category'" in rec.message for rec in caplog.records)


def test_unknown_event_type_returns_none_and_warns(caplog):
    bad = _make("node.weirdthing", category="reasoning")
    with caplog.at_level(logging.WARNING, logger="btagent.ws.engine_event_adapter"):
        result = adapt_engine_event(bad)
    assert result is None
    assert any("unknown event_type" in rec.message for rec in caplog.records)


def test_non_dict_payload_returns_none_and_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="btagent.ws.engine_event_adapter"):
        result = adapt_engine_event("not a dict")  # type: ignore[arg-type]
    assert result is None
    assert any("non-dict" in rec.message for rec in caplog.records)


# --------------------------------------------------------------------------- #
# Round-trip through the wire schema
# --------------------------------------------------------------------------- #


def test_round_trip_through_event_envelope_model_validate():
    """Adapted events serialise cleanly back through the wire schema."""
    event = _make(
        "node.start",
        category="integration",
        node_id="integration.splunk.search",
        node_name="Splunk Search",
        input={"spl": "index=main error"},
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None

    raw = envelope.model_dump_json()
    restored = EventEnvelope.model_validate_json(raw)

    assert restored.type is EventType.TOOL_START
    assert restored.data["tool_name"] == "Splunk Search"
    assert restored.data["input"] == {"spl": "index=main error"}
    assert restored.investigation_id == envelope.investigation_id
    assert restored.id == envelope.id


def test_round_trip_for_error_envelope():
    event = _make(
        "node.error",
        category="reasoning",
        node_id="reasoning.llm_call",
        error="rate limit exceeded",
        error_type="RateLimitError",
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    restored = EventEnvelope.model_validate_json(envelope.model_dump_json())
    assert restored.type is EventType.ERROR
    assert restored.data["source"] == "llm"
    assert restored.data["error_type"] == "RateLimitError"


def test_reasoning_end_falls_back_when_output_lacks_text_key():
    """Output dicts without ``text`` still surface *something* to the UI."""
    event = _make(
        "node.end",
        category="reasoning",
        node_id="reasoning.llm_call",
        output={"content": "alternative content key"},
    )
    envelope = adapt_engine_event(event)
    assert envelope is not None
    assert envelope.type is EventType.OUTPUT
    assert envelope.data["text"] == "alternative content key"
