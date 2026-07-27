"""Types for the agentic CTI → Detection engineering path (issue #113 "do both").

The deterministic STIX → Sigma pipeline
(:mod:`btagent_shared.hunt.cti_to_detection`) converts machine-readable STIX
indicators into Sigma rules with fixed templates. This module adds the
*agentic* counterpart's engine-portable contracts:

* :class:`IntelArtifact` — a prose threat-intel report (untrusted) with a
  content hash for provenance.
* :class:`BehavioralTTP` — one behavioral technique tuple extracted from the
  report by the ``CTIExtractor``.
* :class:`DetectionDraft` — a drafted Sigma rule (deterministic *or*
  LLM-authored) whose :attr:`DetectionDraft.data_sources_required` is populated
  by the ``DataSourceMatcher`` from connected connectors' manifests.
* :class:`DataSourceRequirement` — per-OCSF-class reconciliation detail.

Design constraints (identical to :mod:`btagent_shared.types.detection_proposal`):
- Zero heavy deps: only pydantic + stdlib.
- ``extra="forbid"`` on every model.
- Lowercase StrEnums.
- IDs / content hashes derived deterministically so repeated runs are stable.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import TLP
from btagent_shared.types.connector import OCSFEventClass
from btagent_shared.utils.ids import generate_id

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DraftMethod(StrEnum):
    """How a :class:`DetectionDraft`'s Sigma body was produced.

    ``deterministic`` — fixed templating from the TTP observables (the default,
    always available, no model). ``agentic`` — authored by an injected LLM
    callable. A draft requested as ``agentic`` but produced without a usable
    model records ``deterministic`` (it degraded gracefully).
    """

    DETERMINISTIC = "deterministic"
    AGENTIC = "agentic"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class IntelArtifact(BaseModel):
    """An unstructured threat-intel report fed to the agentic pipeline.

    The ``report_text`` is untrusted operator/vendor prose — every consumer
    fences it in ``<external-data>`` tags before it reaches an LLM. ``sha256``
    is the content hash of ``report_text`` and links every downstream
    :class:`DetectionDraft` back to its source for the PR evidence chain.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Prefixed-ULID artifact id.")
    title: str = Field(default="", description="Human-readable report title.")
    report_text: str = Field(description="Raw prose intel report (untrusted).")
    source: str = Field(default="prose", description="Origin descriptor (e.g. vendor, feed).")
    tlp: TLP = Field(default=TLP.GREEN, description="TLP classification of the report.")
    sha256: str = Field(description="SHA-256 of report_text — provenance / evidence chain.")
    created_at: datetime = Field(description="UTC timestamp the artifact was ingested.")

    @classmethod
    def from_report(
        cls,
        report_text: str,
        *,
        title: str = "",
        source: str = "prose",
        tlp: TLP = TLP.GREEN,
        created_at: datetime | None = None,
    ) -> IntelArtifact:
        """Build an artifact, computing the content hash + id from the report."""
        digest = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
        return cls(
            id=generate_id("intel"),
            title=title,
            report_text=report_text,
            source=source,
            tlp=tlp,
            sha256=digest,
            created_at=created_at or datetime.now(UTC),
        )


class BehavioralTTP(BaseModel):
    """One behavioral technique tuple extracted from an :class:`IntelArtifact`.

    Unlike a STIX indicator (an atomic IOC), a TTP describes *behavior* — the
    ``observables`` are the concrete strings a Sigma rule keys on (command-line
    fragments, process names, URI stems) and ``logsource_category`` is the
    Sigma logsource the behavior lives in (drives the OCSF telemetry mapping).
    """

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(description="MITRE ATT&CK technique id (e.g. 'T1059.001').")
    tactic: str = Field(default="", description="ATT&CK tactic slug (e.g. 'execution').")
    behavior: str = Field(default="", description="Prose description of the observed behavior.")
    observables: list[str] = Field(
        default_factory=list,
        description="Concrete strings the drafted rule matches on (untrusted).",
    )
    logsource_category: str = Field(
        default="process_creation",
        description="Sigma logsource.category the behavior is observed in.",
    )
    logsource_product: str = Field(
        default="", description="Sigma logsource.product, when narrower than a category."
    )
    confidence: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Confidence the TTP is real + rule-worthy.",
    )


class DataSourceRequirement(BaseModel):
    """Reconciliation detail for one OCSF class a draft needs telemetry from."""

    model_config = ConfigDict(extra="forbid")

    ocsf_class: OCSFEventClass = Field(description="Required OCSF event class.")
    satisfied_by: list[str] = Field(
        default_factory=list,
        description="Connected connectors whose manifest emits this OCSF class.",
    )
    covered: bool = Field(description="True when at least one connected connector supplies it.")


class DetectionDraft(BaseModel):
    """A drafted Sigma rule from the agentic detection-engineering path.

    Mirrors :class:`~btagent_shared.types.detection_proposal.DetectionProposal`
    but originates from prose intel rather than a STIX indicator.
    :attr:`data_sources_required` starts empty and is populated by the
    ``DataSourceMatcher`` — reconciling :attr:`ocsf_classes_required` against
    connected connectors' manifest ``ocsf_emits``.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Prefixed-ULID draft id.")
    source_report_sha256: str = Field(
        default="",
        description="SHA-256 of the source IntelArtifact — links the draft to its intel.",
    )
    title: str = Field(description="Human-readable rule title.")
    sigma_yaml: str = Field(description="Complete, valid Sigma rule as a YAML string.")
    method: DraftMethod = Field(description="How the Sigma body was produced (effective method).")
    technique_ids: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique ids covered by the rule."
    )
    tactic: str = Field(default="", description="Primary ATT&CK tactic slug.")
    ocsf_classes_required: list[OCSFEventClass] = Field(
        default_factory=list,
        description="OCSF telemetry classes the rule needs to fire (from the TTP).",
    )
    data_sources_required: list[str] = Field(
        default_factory=list,
        description=(
            "Connected connectors that can supply the required telemetry. Populated "
            "by the DataSourceMatcher from manifest ocsf_emits; empty until matched."
        ),
    )
    data_source_gaps: list[OCSFEventClass] = Field(
        default_factory=list,
        description="Required OCSF classes NO connected connector emits (coverage gaps).",
    )
    data_source_coverage: list[DataSourceRequirement] = Field(
        default_factory=list,
        description="Per-OCSF-class reconciliation detail behind the summary lists.",
    )
    confidence: float = Field(
        default=0.6, ge=0.0, le=1.0, description="Confidence inherited from the source TTP."
    )
    rationale: str = Field(default="", description="Why this rule was drafted.")
    generated_at: datetime = Field(description="UTC timestamp the draft was created.")


__all__ = [
    "BehavioralTTP",
    "DataSourceRequirement",
    "DetectionDraft",
    "DraftMethod",
    "IntelArtifact",
]
