"""Cross-Investigation Pattern Hunter schemas (Phase 6 #120).

The cross-investigation counterpart to the per-entity Behavioral Hunter
(#114) and the rule-driven Hunt Pack Runner (#112). Where those hunt a
single live telemetry stream, this hunts the *corpus of closed
investigations*: the same observable (an IOC, a TLD, a command-line
fragment, an asset, an ASN, a technique) showing up faintly across many
**unrelated** past cases is a weak signal that a slow campaign has been
tunnelling under the SOC's radar.

A :class:`WeakSignal` is one such observable with its source-investigation
provenance; a :class:`WeakSignalCluster` groups similar signals and carries
the explainable rank; a :class:`PatternHuntProposal` turns a high-ranking
cluster into a ready-to-run :class:`~btagent_shared.types.hunt.HuntInput`.

Design notes (kept in lock-step with the rest of ``btagent_shared.types``):

1. **Zero heavy dependencies** — Pydantic only, so the engine / backend /
   tests can all import this tier without pulling LangChain, MCP, etc.
2. **``extra="forbid"`` everywhere** — a typo'd field is a contract bug, not
   a silently-dropped value.
3. **Enum values are lowercase strings** to match ``Severity`` / ``IOCType``
   / ``HuntDomain`` conventions.
4. The dependency-free extraction + clustering + proposal logic lives in
   :mod:`btagent_shared.hunt.pattern`; persistence + corpus-walking live in
   ``backend/btagent_backend/services/pattern_hunt_service.py``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.hunt import HuntInput


class WeakSignalKind(StrEnum):
    """The class of observable a weak signal is keyed on.

    Stored as a lowercase string so adding a kind is a non-destructive
    change. Each kind maps to a distinct extraction path in
    :class:`btagent_shared.hunt.pattern.WeakSignalExtractor`.
    """

    IOC = "ioc"
    TLD = "tld"
    CMDLINE_FRAGMENT = "cmdline_fragment"
    ASSET = "asset"
    ASN = "asn"
    TECHNIQUE = "technique"


class ProposalState(StrEnum):
    """Lifecycle of a :class:`PatternHuntProposal`.

    * ``PROPOSED`` — surfaced by a scan, awaiting analyst review.
    * ``ACCEPTED`` — analyst kicked off the hunt from this proposal.
    * ``DISMISSED`` — analyst marked it not-interesting; the service
      down-weights similar clusters in future scans so the same shape
      doesn't keep re-surfacing.
    * ``SNOOZED`` — temporarily hidden; also down-weights similar future
      surfacing but is explicitly reversible.
    """

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"
    SNOOZED = "snoozed"


class ProposalOutcome(StrEnum):
    """Terminal result of a hunt launched from a proposal (Phase B feedback).

    Persisted here so the closed-loop tuning that lands in Phase B has a
    column to write into; Phase A only ever sets it to ``None``.
    """

    CLEAN = "clean"
    HIT = "hit"


# --------------------------------------------------------------------------- #
# Core domain models
# --------------------------------------------------------------------------- #


class WeakSignal(BaseModel):
    """A single faint observable extracted from the closed-investigation corpus.

    The ``distinct_investigation_count`` is deliberately a stored field
    (rather than ``len(investigation_refs)``): cross-investigation diversity
    is the load-bearing ranking term (see
    :class:`btagent_shared.hunt.pattern.WeakSignalClusterer`), so it is
    computed once at extraction time and pinned, never re-derived from a
    possibly-truncated ref list.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: WeakSignalKind
    value: str = Field(..., min_length=1, max_length=2048)
    # The original :class:`~btagent_shared.types.enums.IOCType` value (e.g.
    # ``"ip"`` / ``"url"`` / ``"hash_sha256"``) for ``kind == IOC`` signals, so
    # the downstream proposal transformer can preserve the known indicator type
    # instead of flattening every exact IOC to ``OTHER`` (which would make the
    # hypothesis generator emit zero hypotheses). ``None`` for non-IOC kinds and
    # for genuinely unknown IOC types (which fall back to ``OTHER`` downstream).
    ioc_type: str | None = Field(
        default=None,
        max_length=30,
        description="Original IOCType value for IOC-kind signals; None otherwise.",
    )
    first_seen: datetime
    last_seen: datetime
    investigation_refs: list[str] = Field(
        default_factory=list,
        description="Investigation ids this signal was observed in (de-duplicated).",
    )
    distinct_investigation_count: int = Field(
        default=0,
        ge=0,
        description="Number of distinct investigations — the diversity term in ranking.",
    )


class WeakSignalCluster(BaseModel):
    """A group of similar weak signals plus its explainable rank.

    ``score`` is produced by the pure clusterer as
    ``frequency × recency × cross-investigation diversity``; ``rationale``
    is the human-readable breakdown of those factors so an analyst can see
    *why* a cluster rose to the top without reading the source code.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    members: list[WeakSignal] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0)
    rationale: str = Field(default="", max_length=4096)


class PatternHuntProposal(BaseModel):
    """A high-ranking cluster turned into a ready-to-run hunt.

    Mirrors :class:`btagent_backend.db.models_pattern.PatternHuntProposalRow`.
    The :class:`~btagent_shared.types.hunt.HuntInput` is fully-formed and
    guaranteed non-empty in at least one of (ttps, iocs, adversaries) by the
    proposal transformer.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    cluster_id: str
    hunt_input: HuntInput
    rationale: str = Field(default="", max_length=4096)
    state: ProposalState = ProposalState.PROPOSED
    outcome: ProposalOutcome | None = None
    created_at: datetime
    updated_at: datetime
