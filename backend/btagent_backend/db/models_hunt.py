"""SQLAlchemy ORM models for the Phase 6 hunt-finding store (#119).

This is the keystone store every Phase 6 hunt source emits into:

* ``hunt_findings`` — individual proactive-hunt results.
* ``hunt_finding_clusters`` — near-duplicate findings grouped by a stable
  clustering signature (see :mod:`btagent_shared.hunt.triage`).
* ``suppression_rules`` — analyst-authored noise suppression, with a
  TTL + re-confirmation lifecycle so suppressions don't silently rot.

All three carry ``org_id`` (FK → ``organizations``) so tenant scoping is
present from day one, matching the workflow / knowledge / playbook stores.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class HuntFindingRow(Base):
    """A single proactive-hunt result."""

    __tablename__ = "hunt_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``HuntSource`` / ``HuntDomain`` enum values — validated at the service
    # layer, stored as strings so a new source/domain doesn't need a
    # destructive migration.
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    domain: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    # ``HuntFindingState`` value.
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    # MITRE technique ids, entity refs, observable refs, evidence provenance.
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    entities: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    observables: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Stable clustering signature (see triage.finding_signature). Denormalised
    # onto the row so the inbox can group without recomputing.
    signature: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    cluster_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("hunt_finding_clusters.id", ondelete="SET NULL"),
        nullable=True,
    )
    suppressed_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("suppression_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    investigation_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        # Composite hot-path indexes (migration 0020): every inbox read
        # filters on org_id and either sorts by created_at or filters by
        # state, so the composites serve filter + sort/filter in one scan
        # (same rationale as 0010_perf_indexes). The single-column org_id
        # index is gone — it's a left-prefix of both composites.
        Index("idx_hunt_findings_org_created", "org_id", "created_at"),
        Index("idx_hunt_findings_org_state", "org_id", "state"),
        Index("idx_hunt_findings_state", "state"),
        Index("idx_hunt_findings_signature", "signature"),
        Index("idx_hunt_findings_cluster_id", "cluster_id"),
        Index("idx_hunt_findings_created_at", "created_at"),
    )


class HuntFindingClusterRow(Base):
    """A group of near-duplicate findings sharing a clustering signature."""

    __tablename__ = "hunt_finding_clusters"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    domain: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="clustered")
    representative_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_hunt_clusters_org_id", "org_id"),
        # One cluster per (org, signature): the service upserts on this.
        Index("idx_hunt_clusters_org_signature", "org_id", "signature", unique=True),
    )


class SuppressionRuleRow(Base):
    """An analyst-authored noise suppression rule with a TTL lifecycle."""

    __tablename__ = "suppression_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    # Serialised ``SuppressionMatch``.
    match: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # ``SuppressionState`` value.
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reconfirm_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Harmful-flag: set when a promoted (confirmed-threat) finding matches this
    # rule's criteria, indicating the rule was hiding real signal.
    # Migration: 0023_suppression_harmful_flag.
    harmful_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    harmful_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    harmful_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_suppression_rules_org_id", "org_id"),
        Index("idx_suppression_rules_state", "state"),
        Index("idx_suppression_rules_reconfirm_at", "reconfirm_at"),
    )


class HuntPackRunRow(Base):
    """History of one scheduled (or ad-hoc) hunt-pack execution (#112).

    Records *what ran and how it landed* — the substrate the future noise
    baselines (#112) read to learn per-rule hit volumes. One row per
    ``run_pack`` invocation: pack identity + version, the backends queried,
    a per-rule hit/error rollup (``rule_stats`` JSON), how many findings the
    run created in the #119 store, and a terminal status.
    """

    __tablename__ = "hunt_pack_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The engine runner's transient ``hrun_`` run id (PackRunResult.run_id) so
    # findings emitted by this run (which carry it in ``evidence.source_run_id``)
    # can be correlated back to this history row.
    run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    pack_id: Mapped[str] = mapped_column(String(200), nullable=False)
    pack_name: Mapped[str] = mapped_column(String(200), nullable=False)
    pack_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # ``SigmaBackendName`` values the run targeted.
    backends: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Per-rule rollup: ``{rule_id: {"title", "hits", "errors"}}``.
    rule_stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Status. ``running`` (in flight — one or more rules still to process; the
    # resume cursor lives in ``progress``) is the transient state a resumable
    # run wears until it lands one of the terminal values: ``completed`` (no
    # execution errors) | ``completed_with_errors`` (some rule×backend
    # executions errored, some succeeded) | ``failed`` (every execution
    # errored, or the run itself raised before finishing) | ``abandoned`` (no
    # worker resumed it inside ``hunt_run_resume_window_minutes``; the sweep
    # was interrupted, not broken, and the distinction matters when an analyst
    # is deciding whether coverage actually ran).
    # ``completed_with_errors`` is 21 chars, hence the 32-char column (widened
    # from 16 in migration 0022, Codex #202 P2). ``running`` added in migration
    # 0055 (#112 resume-from-checkpoint).
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Per-rule resume cursor (#112): ``{"completed_rule_ids": [...]}`` — the
    # rules whose hits have already been converted, ingested, and checkpointed.
    # Written incrementally (one commit per rule) so a worker restart mid-run
    # resumes at the first not-yet-completed rule instead of re-doing finished
    # work. Empty ``{}`` on a legacy row / a run that never checkpointed.
    # Migration 0055_huntpack_resume.
    progress: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # E7 coverage honesty (migration 0069). The runner enforces a
    # rules-per-sweep cap and a per-run deadline; when either stops a run
    # early it sets ``PackRunResult.truncated`` and lists the rules it never
    # got to. Persisting both is the point of the signal: without it a capped
    # sweep is indistinguishable from a clean full one in the history, and an
    # analyst reads "0 hits" as "nothing there" rather than "we didn't look".
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rules_not_run: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # The history list is org-scoped and newest-first.
        Index("idx_hunt_pack_runs_org_started", "org_id", "started_at"),
        Index("idx_hunt_pack_runs_pack_id", "pack_id"),
        # Resume lookup: the newest in-flight run for one org's pack (migration
        # 0055) — org_id + pack_id + status, so a restart finds the row to
        # resume in one index scan.
        Index("idx_hunt_pack_runs_org_pack_status", "org_id", "pack_id", "status"),
    )


class OrgHuntPackRow(Base):
    """A hunt pack installed for one org, with its enable/disable state (#112).

    The per-org pack store the scheduled runner reads instead of the hardcoded
    builtin default: one row per ``(org_id, pack_id)``, where ``pack_id`` is the
    **builtin pack name** (the directory under ``btagent_engine/hunting/packs``,
    e.g. ``windows_baseline``) — the identity ``load_builtin_pack`` takes, not
    the manifest's ``hpack_…`` id that ``hunt_pack_runs.pack_id`` records.

    Absence is meaningful: an org with **no rows** falls back to the builtin
    default set (``hunt_pack_store.DEFAULT_BUILTIN_PACKS``), so existing orgs
    keep running exactly what they ran before this table existed. A row is only
    written when someone explicitly enables or disables a pack.
    """

    __tablename__ = "org_hunt_packs"

    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # Builtin pack name (``load_builtin_pack`` key), e.g. "windows_baseline".
    pack_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    # User id of whoever last flipped the switch (null for system installs).
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        # The runner's question is "which packs are enabled for this org?".
        Index("idx_org_hunt_packs_org_enabled", "org_id", "enabled"),
    )


class NoiseDigestStateRow(Base):
    """Per-org memory of the last noise-digest run (#112).

    Stores the set of ``"pack_id:rule_id"`` keys the previous digest saw as
    chronically noisy, so the scheduled sweep only notifies about rules that
    are NEW since last time. A rule that goes quiet is dropped from the set,
    so if it later turns noisy again the digest re-notifies — regressions
    are signal, not repeats.
    """

    __tablename__ = "noise_digest_state"

    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # Sorted list of "pack_id:rule_id" keys from the last digest.
    noisy_keys: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class HuntPackageRow(Base):
    """A persisted hunt package (#99 / EPIC-2 UC-2.2).

    ``POST /hunts/package`` used to return a transient object that vanished
    when the analyst navigated away; this row makes the artifact durable so
    packages are listable, re-openable, and attachable to cases later. The
    full package is stored as JSON; a few columns are denormalised for the
    history list.
    """

    __tablename__ = "hunt_packages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    source_label: Mapped[str] = mapped_column(String(200), nullable=False, default="advisory")
    extracted_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deduped_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # ATT&CK technique ids derived from the extracted indicators.
    techniques: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    mock_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The full HuntPackage model_dump (queries, sigma drafts, retro report).
    package: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Case lineage: set when the analyst promotes the package into an
    # investigation. SET NULL keeps the package if the case is deleted.
    investigation_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (Index("idx_hunt_packages_org_created", "org_id", "created_at"),)


class ShadowAgentRegistryRow(Base):
    """Governance decision for a discovered shadow agent / MCP server (#121/#117).

    Shadow findings (evidence ``shadow_workload=True``) route to governance,
    not IR: an analyst either *registers* the workload (sanctioned — bring it
    under management) or *sunsets* it (decommission). One row per
    (org, resource); re-governing updates the decision in place so the
    registry reflects the latest ruling, with the originating finding kept
    for lineage.
    """

    __tablename__ = "shadow_agent_registry"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Cloud resource id / identity ref / host the shadow agent was observed at.
    resource_key: Mapped[str] = mapped_column(String(512), nullable=False)
    # Workload kind from the finding evidence (cloud_run_mcp, bedrock_agentcore, ...).
    kind: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    # "registered" | "sunset" — the governance ruling.
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    decided_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_shadow_registry_org_resource", "org_id", "resource_key", unique=True),
        Index("idx_shadow_registry_org_status", "org_id", "status"),
    )


class OrgCustomPackRow(Base):
    """An org-authored hunt pack uploaded as a bundle (#112 slice 2).

    Unlike :class:`OrgHuntPackRow` (enable state over *builtin* packs), this
    row IS the pack: the verbatim ``pack.yaml`` text plus the rule files, as
    validated by the engine's ``load_pack_from_bundle`` at upload time. The
    scheduled sweep re-loads the bundle through that same loader on every run,
    so a row that persists is a row that runs. ``pack_id`` is the manifest's
    (possibly derived) ``hpack_…`` id — the identity ``hunt_pack_runs.pack_id``
    and the noise baseline correlate on — unique per org so re-uploading the
    same versioned pack updates in place rather than duplicating history.

    Uploaded packs are enabled by existence in this slice: delete removes the
    pack from the sweep; there is no separate disable state to drift.
    """

    __tablename__ = "org_custom_packs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The loaded HuntPack.id (manifest id or the deterministic hpack_ hash).
    pack_id: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    manifest_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    # {rule filename -> raw Sigma YAML}, exactly as uploaded/validated.
    rule_files: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_org_custom_packs_org", "org_id"),
        # Re-uploading the same pack identity updates in place.
        Index("idx_org_custom_packs_org_pack", "org_id", "pack_id", unique=True),
    )
