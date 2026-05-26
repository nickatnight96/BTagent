"""Data-category Nodes: shape-bridges and lightweight enrichments.

The ``data`` category covers Nodes that don't reach out to a vendor or
issue an LLM call but are needed in real workflows: shape-bridging
between Nodes whose schemas don't line up (TransformNode), and
deterministic enrichments that operate on text (MitreMapperNode).

Sprint 4A ships two:

* ``TransformNode`` -- generic dict-to-dict mapper (rename / drop /
  set / keep_only) used to plumb data between Nodes whose
  ``extra=forbid`` schemas would otherwise refuse the handoff.
* ``MitreMapperNode`` -- keyword-based MITRE ATT&CK technique
  suggester. Word-boundary matching (the agents-side substring
  matcher had high false positives like ``lateral`` matching
  ``collateral``).
"""

from btagent_engine.data.mitre_mapper import (
    MitreMappedTechnique,
    MitreMapperInput,
    MitreMapperNode,
    MitreMapperOutput,
)
from btagent_engine.data.coverage_gap import (
    CoverageGapInput,
    CoverageGapNode,
    CoverageGapOutput,
    TechniqueRef,
)
from btagent_engine.data.noise_baseline import (
    NoiseBaselineInput,
    NoiseBaselineNode,
    NoiseBaselineOutput,
)
from btagent_engine.data.ocsf_mapper import (
    OCSFMapperInput,
    OCSFMapperNode,
    OCSFMapperOutput,
    UnknownConnectorError,
)
from btagent_engine.data.runbook_compiler import (
    RunbookCompilerInput,
    RunbookCompilerNode,
    RunbookCompilerOutput,
)
from btagent_engine.data.transform import (
    TransformInput,
    TransformNode,
    TransformOutput,
)

__all__ = [
    "CoverageGapInput",
    "CoverageGapNode",
    "CoverageGapOutput",
    "TechniqueRef",
    "MitreMappedTechnique",
    "MitreMapperInput",
    "MitreMapperNode",
    "MitreMapperOutput",
    "NoiseBaselineInput",
    "NoiseBaselineNode",
    "NoiseBaselineOutput",
    "OCSFMapperInput",
    "OCSFMapperNode",
    "OCSFMapperOutput",
    "UnknownConnectorError",
    "RunbookCompilerInput",
    "RunbookCompilerNode",
    "RunbookCompilerOutput",
    "TransformInput",
    "TransformNode",
    "TransformOutput",
]
