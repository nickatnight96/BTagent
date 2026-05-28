"""Add user_mfa table (opt-in TOTP MFA, #144 Phase 1a).

A separate table (NOT a widening of ``users``) holding per-user TOTP MFA
state: a Fernet-encrypted TOTP secret, an ``enabled`` flag (two-step
enroll → confirm), the confirmation timestamp, and a JSON list of
bcrypt-hashed single-use recovery codes.

``user_id`` is both PK and FK → ``users.id`` (ON DELETE CASCADE), so MFA is
1:1 with a user and a user with no MFA simply has no row here (the default;
all seeded CI users are in this state, so the login flow is unchanged for
them).

Revision ID: 0012_mfa
Revises: 0011_tlp_policies
Create Date: 2026-05-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_mfa"
down_revision: str | None = "0011_tlp_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_mfa",
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("secret_enc", sa.Text, nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean,
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "recovery_codes_enc",
            sa.Text,
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("user_mfa")
