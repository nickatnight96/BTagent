"""SQLAlchemy ORM model for connector credential references (#100).

One table, org-scoped:

* ``connector_credentials`` — the per-org binding between an installed
  connector and the ``${secret:...}`` reference that resolves its
  credential material at call time. **The row stores only the reference
  string**, never the secret itself; the actual material lives in the
  resolver backend (Vault / AWS Secrets Manager / env), so this table is
  safe to read at ``credential:view`` and carries nothing to leak.

Uniqueness is ``(org_id, connector_name)`` — one credential binding per
connector per org; re-binding upserts.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class ConnectorCredentialRow(Base):
    """One org's credential-reference binding for a connector."""

    __tablename__ = "connector_credentials"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The connector this credential binds to (matches ConnectorManifest.name).
    connector_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # A single ``${secret:...}`` / ``${env:...}`` reference — validated on
    # write (is_secret_reference); never raw secret material.
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    # Optional human label ("prod service account", "read-only key").
    label: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_connector_credentials_org", "org_id"),
        # One credential binding per connector per org — writes upsert on this.
        Index(
            "idx_connector_credentials_unique",
            "org_id",
            "connector_name",
            unique=True,
        ),
    )
