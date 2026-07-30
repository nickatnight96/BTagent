"""Behavioral Hunter schemas (Phase 6 #114).

The baseline-driven counterpart to the Hunt Pack Runner (#112). Per-entity
behavioral profiles live in pgvector (same substrate as the Knowledge RAG);
new events are scored against the entity's centroid + frequency map by the
pure logic in :mod:`btagent_shared.hunt.behavioral`. Outliers escalate into
the #119 HuntFinding queue.

These are the data contracts; the dependency-free scoring lives in
:mod:`btagent_shared.hunt.behavioral`; persistence + detection wiring lives
in ``backend/btagent_backend/services/behavioral_service.py``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EntityKind(StrEnum):
    """What a behavioral profile is keyed on."""

    USER = "user"
    HOST = "host"
    SERVICE_PRINCIPAL = "service_principal"
    IP = "ip"


class ProfileType(StrEnum):
    """The behavioral dimensions tracked per entity.

    Each profile_type maintains its own centroid + frequency map; an entity
    has one profile per (entity_id, profile_type, computed_at) window.
    """

    CMDLINE_EMBEDDING = "cmdline_embedding"
    PROCESS_TREE_PATTERN = "process_tree_pattern"
    IDENTITY_ACTION_SEQUENCE = "identity_action_sequence"
    NETWORK_EGRESS_PROFILE = "network_egress_profile"


class IntentLabel(StrEnum):
    """LLM-rated outlier intent (Phase A persists, Phase A's classifier is the
    follow-up that fills it in)."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# --------------------------------------------------------------------------- #
# Core domain models
# --------------------------------------------------------------------------- #


class BehavioralEntity(BaseModel):
    """A subject of behavioral profiling — a user, host, service principal, or IP."""

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    kind: EntityKind
    canonical_id: str = Field(..., min_length=1, max_length=512)
    first_seen: datetime
    last_seen: datetime
    enrichment: dict[str, Any] = Field(default_factory=dict)


class BehavioralProfile(BaseModel):
    """One per-entity behavioral baseline for a single ``profile_type``.

    Centroid lives in pgvector (text embeddings via the existing
    embedding-service); the frequency map is a bounded top-K of observed
    pattern keys → counts so it stays small in JSONB.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    entity_id: str
    profile_type: ProfileType
    # Optional because some profile_types (e.g. ``process_tree_pattern``) may
    # use the frequency map without a meaningful centroid.
    centroid: list[float] | None = None
    frequency_map: dict[str, int] = Field(default_factory=dict)
    pattern_count: int = 0
    sample_size: int = 0
    window_start: datetime
    window_end: datetime
    computed_at: datetime
    updated_at: datetime


class BehavioralOutlier(BaseModel):
    """A single event flagged as anomalous against an entity's profile."""

    model_config = ConfigDict(extra="forbid")

    id: str
    org_id: str
    entity_id: str
    profile_type: ProfileType
    event_id: str = Field(..., min_length=1, max_length=200)
    # The pattern key the frequency floor matched on (process lineage
    # ``parent>child`` for the cmdline profile). Optional: rows written before
    # the column existed carry ``None``.
    event_pattern_key: str | None = Field(default=None, max_length=512)
    cosine_distance: float = Field(..., ge=0.0, le=2.0)
    # Rank in the entity's frequency map (1 = most common, 0 = absent).
    frequency_rank: int = Field(default=0, ge=0)
    raw_event_excerpt: str = Field(default="", max_length=4096)
    intent_label: IntentLabel | None = None
    intent_rationale: str | None = None
    promoted_to_finding_id: str | None = None
    created_at: datetime


# --------------------------------------------------------------------------- #
# Request / response payloads for ``/api/v1/behavioral/*`` (#114 Phase A)
# --------------------------------------------------------------------------- #


class SetIntentRequest(BaseModel):
    """Body for ``POST /behavioral/outliers/{id}/intent`` — analyst triage.

    The analyst (or the IntentClassifier acting on their behalf) records a
    verdict + rationale; mirrors the service's :func:`set_intent` signature.
    """

    model_config = ConfigDict(extra="forbid")

    intent_label: IntentLabel
    rationale: str = Field(..., min_length=1, max_length=4096)


class PromoteOutlierRequest(BaseModel):
    """Body for ``POST /behavioral/outliers/{id}/promote`` — escalate to #119."""

    model_config = ConfigDict(extra="forbid")

    technique_ids: list[str] = Field(default_factory=list)


class PromoteOutlierResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str


class BehavioralOutlierListResponse(BaseModel):
    """Paginated, org-scoped list of behavioral outliers."""

    model_config = ConfigDict(extra="forbid")

    items: list[BehavioralOutlier]
    total: int


# --------------------------------------------------------------------------- #
# "Why is this an outlier?" — explainability payloads (#114 Phase B)
# --------------------------------------------------------------------------- #


class ExemplarSource(StrEnum):
    """Where a "this is what normal looks like" example came from."""

    # A pattern from THIS entity's own latest baseline window.
    ENTITY_BASELINE = "entity_baseline"
    # The most common pattern of a peer entity whose baseline centroid is a
    # pgvector nearest neighbour of this entity's — "entities that behave like
    # this one consider this normal".
    PEER_BASELINE = "peer_baseline"


class BaselineExemplar(BaseModel):
    """One "most-similar normal example" beside an anomalous event.

    Only ever carries scores the backend actually computes:

    * ``token_similarity`` — lexical token overlap with the outlier's pattern
      key (``btagent_shared.hunt.behavioral.pattern_similarity``). Set for
      entity-baseline exemplars; the per-event embedding is not retained, so
      individual baseline patterns cannot be ranked by cosine distance.
    * ``centroid_distance`` — the pgvector cosine distance between the peer's
      baseline centroid and this entity's. Set for peer-baseline exemplars.

    Whichever is not applicable stays ``None`` — the UI must say "unavailable"
    rather than substitute a number.
    """

    model_config = ConfigDict(extra="forbid")

    pattern_key: str
    source: ExemplarSource
    # How many times the pattern was observed in the baseline window it came from.
    observation_count: int = Field(default=0, ge=0)
    # 1-indexed rank within that baseline's frequency map (0 = not ranked).
    frequency_rank: int = Field(default=0, ge=0)
    token_similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    centroid_distance: float | None = Field(default=None, ge=0.0, le=2.0)
    # Populated for peer exemplars so the analyst knows whose normal this is.
    entity_id: str | None = None
    entity_canonical_id: str | None = None
    profile_id: str | None = None


class ExplainSignal(BaseModel):
    """One contributing signal behind a detection, or an honest "unavailable".

    ``available=False`` means the platform does not persist this signal per
    outlier (e.g. the run-time detection thresholds); ``value`` is then ``None``
    and ``detail`` explains why. Nothing here is a score the detector doesn't
    already produce.
    """

    model_config = ConfigDict(extra="forbid")

    key: str
    label: str
    value: str | None = None
    detail: str
    available: bool = True


class BaselineSummary(BaseModel):
    """The baseline window an outlier was scored against."""

    model_config = ConfigDict(extra="forbid")

    profile_id: str
    profile_type: ProfileType
    sample_size: int = 0
    pattern_count: int = 0
    has_centroid: bool = False
    window_start: datetime
    window_end: datetime
    computed_at: datetime


class OutlierExplanation(BaseModel):
    """Everything the UI needs to answer "why is this an outlier?".

    The anomalous event, the entity's current baseline, the most-similar normal
    examples, and the signals the detector computed — plus ``notes`` recording
    anything that could not be produced (no baseline, no centroid, peer search
    unavailable), so the page can say so instead of rendering a blank panel.
    """

    model_config = ConfigDict(extra="forbid")

    outlier: BehavioralOutlier
    entity_id: str
    entity_kind: EntityKind
    entity_canonical_id: str
    anomalous_event: str = ""
    event_pattern_key: str | None = None
    baseline: BaselineSummary | None = None
    exemplars: list[BaselineExemplar] = Field(default_factory=list)
    signals: list[ExplainSignal] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
