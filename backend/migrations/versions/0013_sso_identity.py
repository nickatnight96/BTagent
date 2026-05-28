"""Add sso_identity table + make users.password_hash nullable (#144 Phase 1b).

Generic OIDC SSO with JIT (just-in-time) provisioning. An ``sso_identity`` row
links a local ``users`` row to an external IdP identity, keyed by the
``(provider, subject)`` pair (the IdP-issued ``sub`` claim is the stable
identifier — emails can change, ``sub`` does not).

``users.password_hash`` is widened to NULLABLE: a user that only ever
authenticates through an IdP (JIT-provisioned, never set a local password)
has no local credential. Existing/seeded users keep their hash, so the local
password login path is unchanged for them.

Revision ID: 0013_sso_identity
Revises: 0012_mfa
Create Date: 2026-05-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_sso_identity"
down_revision: str | None = "0012_mfa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sso_identity",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        # Logical provider key (the ``{provider}`` path segment, e.g. "okta").
        sa.Column("provider", sa.String(100), nullable=False),
        # IdP-issued ``sub`` claim — stable across email/profile changes.
        sa.Column("subject", sa.String(255), nullable=False),
        # Email at link time (informational; ``subject`` is the join key).
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # One IdP identity maps to exactly one local user.
        sa.UniqueConstraint("provider", "subject", name="uq_sso_identity_provider_subject"),
    )
    op.create_index("idx_sso_identity_user_id", "sso_identity", ["user_id"])

    # Widen password_hash to NULLABLE so JIT/SSO-only users (no local password)
    # are representable. Seeded/local users keep their existing hash.
    op.alter_column(
        "users",
        "password_hash",
        existing_type=sa.String(255),
        nullable=True,
    )


def downgrade() -> None:
    # Backfill any NULL password hashes before re-imposing NOT NULL, otherwise
    # the alter would fail on SSO-only rows.
    op.execute("UPDATE users SET password_hash = '' WHERE password_hash IS NULL")
    op.alter_column(
        "users",
        "password_hash",
        existing_type=sa.String(255),
        nullable=False,
    )
    op.drop_index("idx_sso_identity_user_id", table_name="sso_identity")
    op.drop_table("sso_identity")
