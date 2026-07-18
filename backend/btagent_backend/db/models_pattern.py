"""SQLAlchemy ORM models for the Cross-Investigation Pattern Hunter (#120).

Two tables, both org-scoped + indexed:

* ``weak_signals`` — the de-duplicated faint observables extracted from the
  closed-investigation corpus. One row per ``(org_id, kind, value)``;
  ``distinct_investigation_count`` is the pinned cross-case diversity term
  (see :mod:`btagent_shared.hunt.pattern`). ``investigation_refs`` is a JSONB
  ``list[str]`` of the source investigation ids.
* ``pattern_hunt_proposals`` — a ranked cluster turned into a ready-to-run
  ``HuntInput`` plus its rationale + lifecycle state. The dismiss/snooze
  states feed the service's down-weighting of similar future surfacing.

Centroid / embedding storage is intentionally absent: Phase A clusters by
exact ``(kind, value)`` over the corpus, so no nearest-neighbor lookup is
needed (mirrors the Behavioral Hunter's Phase-A JSONB choice).
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class WeakSignalRow(Base):
    """One faint observable recurring across the closed-investigation corpus."""

    __tablename__ = "weak_signals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``WeakSignalKind`` value — stored as string so a new kind doesn't require
    # a destructive migration.
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    # JSONB list[str] of source investigation ids (de-duplicated).
    investigation_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Pinned at extraction time — the dominant ranking term; never re-derived.
    distinct_investigation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_weak_signals_org_id", "org_id"),
        # Upsert key: one row per (org, kind, value).
        Index("idx_weak_signals_unique", "org_id", "kind", "value", unique=True),
        Index("idx_weak_signals_diversity", "org_id", "distinct_investigation_count"),
    )


class PatternHuntProposalRow(Base):
    """A high-ranking weak-signal cluster turned into a hunt proposal."""

    __tablename__ = "pattern_hunt_proposals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Stable cluster signature (kind+value-derived) so a re-scan can find +
    # update an existing proposal rather than spamming duplicates.
    cluster_id: Mapped[str] = mapped_column(String(128), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Serialised HuntInput (model_dump) — the ready-to-run hunt payload.
    hunt_input: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    rationale: Mapped[str] = mapped_column(Text, default="")
    # Analyst triage notes accumulated across dismiss/snooze/accept
    # transitions — kept separate from the generated ``rationale`` so the
    # "why this surfaced" text stays pristine (#218 Phase C). Null until an
    # analyst first provides a note.
    triage_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ``ProposalState`` value.
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    # ``ProposalOutcome`` value — nullable; only set when a launched hunt
    # completes (Phase B closed-loop).
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_pattern_proposals_org_id", "org_id"),
        # One live proposal per (org, cluster) — re-scans upsert on this.
        Index("idx_pattern_proposals_cluster", "org_id", "cluster_id", unique=True),
        Index("idx_pattern_proposals_state", "org_id", "state"),
        Index("idx_pattern_proposals_score", "org_id", "score"),
    )


class HuntPlanRow(Base):
    """A compiled (or compiling) HuntPlan for an accepted proposal (#120 Phase C).

    ``status`` is the row-level compile lifecycle — ``pending`` (accept
    recorded, compile not finished), ``ready`` (``plan`` holds the full
    serialised :class:`~btagent_shared.types.hunt.HuntPlan`), or ``failed``
    (``error`` says why; the proposal stays accepted so a re-compile can be
    wired later). The plan JSON carries its own ``HuntPlanState`` — the two
    lifecycles are deliberately separate: this row tracks *compilation*, the
    plan tracks *execution*.
    """

    __tablename__ = "hunt_plans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    proposal_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("pattern_hunt_proposals.id", ondelete="CASCADE"),
        nullable=False,
    )
    # "pending" | "ready" | "failed" — compile lifecycle, not HuntPlanState.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    # Serialised HuntPlan (model_dump mode="json"); None until compiled.
    plan: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_hunt_plans_org_id", "org_id"),
        # One plan per proposal — accept is idempotent on this.
        Index("idx_hunt_plans_proposal", "proposal_id", unique=True),
        Index("idx_hunt_plans_status", "org_id", "status"),
    )


class PlanRunRow(Base):
    """History of one HuntPlan execution (#120 follow-up, mirrors hunt_pack_runs).

    One row per ``execute_plan_and_ingest`` invocation. The ``last_run`` blob
    riding alongside the plan JSON in ``hunt_plans.plan`` remains the
    quick-glance summary (backward compatible); this table is the full
    per-run history — what ran, against which TTPs, how it landed, and how
    many findings it created — so repeated executions stop overwriting each
    other's record.
    """

    __tablename__ = "plan_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_row_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("hunt_plans.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalised pivots: the proposal the plan compiled from and the
    # compiled HuntPlan's own id (both already inside the plan JSON, kept as
    # columns so history queries never parse JSONB).
    proposal_id: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # The engine runner's transient ``hrun_`` id (PlanRunResult.run_id) —
    # findings created by this run carry it in ``evidence.plan_run_id``.
    run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Per-TTP rollup: ``{ttp_id: {"hits": n, "errors": [..]}}`` — same shape
    # as the plan JSON's ``last_run.per_ttp``.
    ttp_stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # ``completed`` | ``completed_with_errors`` | ``failed`` — same derivation
    # as hunt_pack_runs (every TTP×backend execution errored ⇒ failed).
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # History lists are org-scoped / per-plan and newest-first.
        Index("idx_plan_runs_org_started", "org_id", "started_at"),
        Index("idx_plan_runs_plan_row", "plan_row_id", "started_at"),
        Index("idx_plan_runs_proposal", "org_id", "proposal_id"),
    )
