"""Enrichment Nodes -- regex IOC extraction, severity scoring, dedup.

These three Nodes port logic that historically lived in the legacy
LangGraph orchestrator (``agents/btagent_agents/orchestrator/nodes.py``)
and the enrichment plugin's ``dedup`` LangChain tool. They are
re-implemented as standalone engine Nodes so that:

* The compiler can wire them into any workflow YAML, not just the
  hard-coded enrichment subgraph.
* The canvas UI can drag-and-drop them as palette items.
* Unit tests have no dependency on ``btagent_agents``.

Sprint 4B port of three Sprint 3D template TODOs.

Each Node is registered with ``NodeCategory.DATA`` -- the enum does not
yet have an ENRICHMENT bucket. See the in-file TODOs for the candidate
enum extension once a fourth+ enrichment Node lands.
"""

from btagent_engine.enrichment.dedup_iocs import (
    DedupIOCsInput,
    DedupIOCsNode,
    DedupIOCsOutput,
)
from btagent_engine.enrichment.extract_iocs import (
    ExtractedIOC,
    ExtractIOCsInput,
    ExtractIOCsNode,
    ExtractIOCsOutput,
)
from btagent_engine.enrichment.score_severity import (
    ScoreSeverityInput,
    ScoreSeverityNode,
    ScoreSeverityOutput,
)

__all__ = [
    "DedupIOCsInput",
    "DedupIOCsNode",
    "DedupIOCsOutput",
    "ExtractIOCsInput",
    "ExtractIOCsNode",
    "ExtractIOCsOutput",
    "ExtractedIOC",
    "ScoreSeverityInput",
    "ScoreSeverityNode",
    "ScoreSeverityOutput",
]
