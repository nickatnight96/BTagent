"""Add playbook and playbook_executions tables.

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Playbooks table
    op.create_table(
        "playbooks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("version", sa.String(20), nullable=False, server_default="1.0"),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("yaml_content", sa.Text, nullable=False),
        sa.Column("trigger_type", sa.String(50), nullable=False),
        sa.Column("trigger_config", JSONB, server_default="{}"),
        sa.Column(
            "created_by",
            sa.String(64),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("is_active", sa.Boolean, server_default="true"),
    )
    op.create_index("idx_playbooks_is_active", "playbooks", ["is_active"])
    op.create_index("idx_playbooks_trigger_type", "playbooks", ["trigger_type"])
    op.create_index("idx_playbooks_created_at", "playbooks", ["created_at"])

    # Playbook executions table
    op.create_table(
        "playbook_executions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "playbook_id",
            sa.String(64),
            sa.ForeignKey("playbooks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("trigger_data", JSONB, server_default="{}"),
        sa.Column("step_results", JSONB, server_default="{}"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )
    op.create_index(
        "idx_pbe_playbook_id", "playbook_executions", ["playbook_id"]
    )
    op.create_index(
        "idx_pbe_investigation_id", "playbook_executions", ["investigation_id"]
    )
    op.create_index("idx_pbe_status", "playbook_executions", ["status"])
    op.create_index("idx_pbe_started_at", "playbook_executions", ["started_at"])


def downgrade() -> None:
    op.drop_table("playbook_executions")
    op.drop_table("playbooks")
