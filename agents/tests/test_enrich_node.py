"""Unit tests for the orchestrator enrich_node → Enrichment plugin wiring.

``_enrich_node`` in the root investigation graph used to be a placeholder that
returned "IOC enrichment is not yet implemented". It now delegates to
``nodes.enrich_node``, which fans the investigation's IOCs out to the
enrichment plugin's ``bulk_enrich`` tool (mock-first CTI) and merges the
verdicts + confidence back onto each IOC.

Coverage:
- IOCs get an ``enrichment`` block merged, with confidence lifted off the
  auto-extraction placeholder, and the malicious count in the summary is
  self-consistent with the per-IOC flags.
- Empty-IOC investigations short-circuit with a "nothing to enrich" message
  and don't touch ``iocs``.
- The state contract: one message, updated iocs (replace semantics), a
  timeline entry, current_agent, status.
- graph._enrich_node delegates to nodes.enrich_node (the wiring itself).
"""

from __future__ import annotations

import re
from typing import Any

from btagent_shared.types.enums import InvestigationStatus

from btagent_agents.orchestrator.nodes import enrich_node


def _ioc(ioc_type: str, value: str) -> dict[str, Any]:
    return {
        "id": f"ioc_{value}",
        "investigation_id": "inv_test",
        "type": ioc_type,
        "value": value,
        "confidence": 0.5,
        "source": "auto_extraction",
        "context": "",
    }


def _state(iocs: list[dict]) -> dict[str, Any]:
    return {
        "investigation_id": "inv_test",
        "iocs": iocs,
        "timeline": [],
        "messages": [],
    }


class TestEnrichNode:
    def test_enriches_and_merges_onto_iocs(self) -> None:
        iocs = [_ioc("ip", "203.0.113.10"), _ioc("domain", "evil-c2.example.net")]
        out = enrich_node(_state(iocs))

        assert out["current_agent"] == "enrich"
        assert out["status"] is InvestigationStatus.INVESTIGATING
        assert len(out["messages"]) == 1

        enriched = out["iocs"]
        assert len(enriched) == len(iocs)
        for ioc in enriched:
            assert "enrichment" in ioc
            enr = ioc["enrichment"]
            assert isinstance(enr["confidence"], (int, float))
            assert isinstance(enr["malicious"], bool)
            # Confidence is lifted off the 0.5 auto-extraction placeholder.
            assert ioc["confidence"] == enr["confidence"]

    def test_summary_malicious_count_is_self_consistent(self) -> None:
        iocs = [
            _ioc("ip", "198.51.100.7"),
            _ioc("domain", "phish.example.org"),
            _ioc("ip", "203.0.113.20"),
        ]
        out = enrich_node(_state(iocs))
        content = out["messages"][0].content

        reported = int(re.search(r"(\d+) flagged malicious", content).group(1))
        actual = sum(1 for i in out["iocs"] if i["enrichment"]["malicious"])
        assert reported == actual
        assert f"Enriched {len(iocs)} of {len(iocs)} IOCs" in content

    def test_timeline_entry_recorded(self) -> None:
        out = enrich_node(_state([_ioc("ip", "203.0.113.30")]))
        assert len(out["timeline"]) == 1
        entry = out["timeline"][0]
        assert entry["event_type"] == "iocs_enriched"
        assert entry["actor"] == "enrich_agent"

    def test_no_iocs_short_circuits(self) -> None:
        out = enrich_node(_state([]))
        assert "iocs" not in out  # untouched — no replace
        assert out["current_agent"] == "enrich"
        assert "nothing to enrich" in out["messages"][0].content.lower()

    def test_preserves_ioc_the_enricher_did_not_return(self) -> None:
        # An unknown IOC type still round-trips (bulk_enrich enriches it via the
        # default source), so every input IOC survives the merge.
        iocs = [_ioc("ip", "203.0.113.40"), _ioc("mac", "00:11:22:33:44:55")]
        out = enrich_node(_state(iocs))
        values = {i["value"] for i in out["iocs"]}
        assert values == {"203.0.113.40", "00:11:22:33:44:55"}


class TestGraphDelegation:
    def test_graph_enrich_node_delegates(self) -> None:
        from btagent_agents.orchestrator.graph import _enrich_node

        out = _enrich_node(_state([_ioc("ip", "203.0.113.50")]))
        # Same real enrichment output — not the old placeholder text.
        assert out["current_agent"] == "enrich"
        assert "enrichment" in out["iocs"][0]
        assert "not yet implemented" not in out["messages"][0].content
