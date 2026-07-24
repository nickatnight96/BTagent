"""SQLAlchemy ORM models for BTagent."""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


# Default organization id used to seed existing rows during the org-scoping
# migration and as a fallback in tests / single-tenant deployments.
DEFAULT_ORG_ID = "org_default"


class OrganizationRow(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Phase A1 (schema): org_id is required.  Until Phase B1 wires routes to
    # set org_id from the authenticated user, we default to the seeded
    # ``org_default`` row so existing call sites continue to function.
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        default=DEFAULT_ORG_ID,
    )
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # Phase 1b (#144): NULLABLE. SSO/JIT-provisioned users authenticate at the
    # IdP and have no local password; ``None`` here means "no local credential".
    # The local-password login path treats a missing hash as "cannot log in
    # with a password" (see ``api/v1/auth.py::login``).
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("idx_users_org_id", "org_id", "id"),)


class SSOIdentityRow(Base):
    """Links a local ``users`` row to an external IdP identity (#144 Phase 1b).

    The natural key is ``(provider, subject)`` — the IdP-issued ``sub`` claim is
    stable, while emails/usernames can change. JIT provisioning looks up this
    pair on every SSO callback: a hit reuses the linked user; a miss
    find-or-creates a user (by email) and inserts a new row here.
    """

    __tablename__ = "sso_identity"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("provider", "subject", name="uq_sso_identity_provider_subject"),
        Index("idx_sso_identity_user_id", "user_id"),
    )


class InvestigationRow(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        default=DEFAULT_ORG_ID,
    )
    case_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    tlp_level: Mapped[str] = mapped_column(String(20), nullable=False, default="green")
    # HITL autonomy posture for agent work under this investigation
    # ("L0".."L4"). Inherited by workflow runs linked to the investigation.
    autonomy_level: Mapped[str] = mapped_column(String(8), nullable=False, default="L2")
    assigned_to: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    template: Mapped[str | None] = mapped_column(String(100), nullable=True)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    iocs: Mapped[list["IOCRow"]] = relationship(back_populates="investigation", cascade="all")
    events: Mapped[list["EventRow"]] = relationship(back_populates="investigation", cascade="all")
    timeline_entries: Mapped[list["TimelineEntryRow"]] = relationship(
        back_populates="investigation", cascade="all"
    )
    containment_actions: Mapped[list["ContainmentActionRow"]] = relationship(
        back_populates="investigation", cascade="all"
    )
    evidence: Mapped[list["EvidenceRow"]] = relationship(
        back_populates="investigation", cascade="all"
    )

    __table_args__ = (
        Index("idx_investigations_status", "status"),
        Index("idx_investigations_created", "created_at"),
        Index("idx_investigations_severity", "severity"),
        Index("idx_investigations_org_id", "org_id", "id"),
        # #146 perf: covers list_investigations org_id filter + created_at sort.
        Index("idx_investigations_org_created", "org_id", "created_at"),
        # #146 perf: plain-analyst ownership filter (WHERE assigned_to = :uid).
        Index("idx_investigations_assigned_to", "assigned_to"),
    )


class IOCRow(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        default=DEFAULT_ORG_ID,
    )
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(30), nullable=False)
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    tlp_level: Mapped[str] = mapped_column(String(20), default="green")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    context: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(200), default="")
    enrichment: Mapped[dict] = mapped_column(JSONB, default=dict)

    # UC-5.2 notebook annotations (#108): analyst-owned metadata layered on
    # the evidence record — pin for the case notebook, free-form tags, a
    # working note, and the analyst's disposition call.
    pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    analyst_note: Mapped[str] = mapped_column(Text, default="")
    disposition: Mapped[str] = mapped_column(String(30), default="")

    investigation: Mapped["InvestigationRow"] = relationship(back_populates="iocs")

    __table_args__ = (
        Index("idx_iocs_value", "value"),
        Index("idx_iocs_investigation", "investigation_id"),
        Index("idx_iocs_type", "type"),
        Index("idx_iocs_org_id", "org_id", "id"),
        # #146 perf: covers list_iocs/search investigation_id filter +
        # first_seen DESC sort in a single index scan.
        Index("idx_iocs_investigation_first_seen", "investigation_id", "first_seen"),
    )


class TimelineEntryRow(Base):
    __tablename__ = "timeline_entries"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), default="")
    event_type: Mapped[str] = mapped_column(String(100), default="")
    evidence_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("evidence.id"), nullable=True
    )
    technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)

    investigation: Mapped["InvestigationRow"] = relationship(back_populates="timeline_entries")

    __table_args__ = (Index("idx_timeline_investigation_ts", "investigation_id", "timestamp"),)


class ContainmentActionRow(Base):
    __tablename__ = "containment_actions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="proposed")
    initiated_by: Mapped[str] = mapped_column(String(200), default="")
    approved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    initiated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    investigation: Mapped["InvestigationRow"] = relationship(back_populates="containment_actions")


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        default=DEFAULT_ORG_ID,
    )
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    content_ref: Mapped[str] = mapped_column(String(1000), default="")
    hash_sha256: Mapped[str] = mapped_column(String(64), default="")
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_by: Mapped[str] = mapped_column(String(200), default="")

    investigation: Mapped["InvestigationRow"] = relationship(back_populates="evidence")

    __table_args__ = (Index("idx_evidence_org_id", "org_id", "id"),)


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, default=dict)
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped["InvestigationRow"] = relationship(back_populates="events")

    __table_args__ = (
        Index("idx_events_investigation_ts", "investigation_id", "timestamp"),
        Index("idx_events_type", "type"),
    )


class AuditLogRow(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, autoincrement=True, unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    resource: Mapped[str] = mapped_column(String(500), default="")
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")

    __table_args__ = (
        Index("idx_audit_seq", "seq"),
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_actor", "actor"),
    )


class CostTrackingRow(Base):
    __tablename__ = "cost_tracking"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("idx_cost_investigation", "investigation_id"),
        Index("idx_cost_timestamp", "timestamp"),
    )


class NotificationRow(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str] = mapped_column(Text, default="")
    investigation_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    # In-app route the bell navigates to on click (e.g. "/hunt",
    # "/workflows/wf_x"). Falls back to the investigation deep-link when
    # absent. App-relative paths only — never a full URL.
    link: Mapped[str | None] = mapped_column(String(512), nullable=True)
    read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("idx_notifications_user", "user_id"),
        Index("idx_notifications_user_read", "user_id", "read"),
        Index("idx_notifications_created", "created_at"),
    )


class NotificationPrefRow(Base):
    """Per-user notification preferences — muted in-app notification types.

    Enforced at the ``NotificationService.send_inapp`` chokepoint, so every
    producer (investigation outcomes, HITL pauses, critical findings, noise
    digests, future ones) respects a mute without knowing about it. Muting
    affects in-app delivery only; nothing here touches audit or Slack.
    """

    __tablename__ = "notification_prefs"

    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # Notification ``type`` values the user has muted (e.g. "noise_digest").
    muted_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class OrgConfigRow(Base):
    __tablename__ = "org_config"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    value: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (Index("idx_org_config_key", "key", unique=True),)


class TLPPolicyRow(Base):
    """A CISO-approved, org-scoped exception to the default-deny egress gate.

    EPIC-7 UC-7.2. Mirrors :class:`btagent_shared.security.tlp_policy.TLPPolicy`:
    an ``allow`` / ``deny`` / ``downgrade_then_allow`` action with optional
    match conditions (``egress_kinds`` / ``applies_to_tlp`` stored as JSON
    string arrays; empty == any) plus governance metadata.
    """

    __tablename__ = "tlp_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    egress_kinds: Mapped[list] = mapped_column(JSONB, default=list)
    applies_to_tlp: Mapped[list] = mapped_column(JSONB, default=list)
    downgrade_to: Mapped[str | None] = mapped_column(String(20), nullable=True)
    approver_id: Mapped[str] = mapped_column(String(200), default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (Index("idx_tlp_policies_org_id", "org_id"),)
