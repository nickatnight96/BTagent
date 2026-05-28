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
    cosine_distance: float = Field(..., ge=0.0, le=2.0)
    # Rank in the entity's frequency map (1 = most common, 0 = absent).
    frequency_rank: int = Field(default=0, ge=0)
    raw_event_excerpt: str = Field(default="", max_length=4096)
    intent_label: IntentLabel | None = None
    intent_rationale: str | None = None
    promoted_to_finding_id: str | None = None
    created_at: datetime
