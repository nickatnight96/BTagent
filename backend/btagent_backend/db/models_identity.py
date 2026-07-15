"""SQLAlchemy ORM models for the identity plane (#116 follow-up).

One table, org-scoped + indexed:

* ``oauth_grants`` — the first-class principal × app grant store the #216
  read-derive endpoint promised as its deliberate follow-up. Rows are written
  at ingest time (see ``identity_grant_service.upsert_grant_from_finding``,
  hooked into ``hunt_triage_service.record_finding``) whenever an
  identity-domain finding carries a complete grant tuple. Uniqueness is
  ``(org_id, provider, principal_id, app_id)`` — the exact dedup key the
  read-derive endpoint used, so semantics carry over unchanged: a newer
  observation of the same grant refreshes scopes / usage / revocation.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class OAuthGrantRow(Base):
    """One OAuth permission grant in the principal↔app grant graph."""

    __tablename__ = "oauth_grants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``IdentityProvider`` value (okta / entra / google_workspace / generic).
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(512), nullable=False)
    app_id: Mapped[str] = mapped_column(String(512), nullable=False)
    app_display_name: Mapped[str] = mapped_column(String(300), default="")
    # JSONB list[str] of normalised OAuth scope strings.
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # ``OAuthConsentType`` value.
    consent_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Provenance: the most recent finding that observed this grant.
    source_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Timestamp of that observation — newest-wins refresh anchor (same
    # semantics as the read-derive endpoint's created_at merge).
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_oauth_grants_org_id", "org_id"),
        # The read-derive dedup key, now enforced at the schema layer.
        Index(
            "idx_oauth_grants_tuple",
            "org_id",
            "provider",
            "principal_id",
            "app_id",
            unique=True,
        ),
        Index("idx_oauth_grants_principal", "org_id", "principal_id"),
    )
