"""Add MITRE ATT&CK tables.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # MITRE ATT&CK techniques
    op.create_table(
        "mitre_techniques",
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("tactic", sa.String(100), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("platforms", JSONB, server_default="[]"),
        sa.Column("data_sources", JSONB, server_default="[]"),
        sa.Column("detection", sa.Text, server_default=""),
        sa.Column("url", sa.String(500), server_default=""),
        sa.Column("is_subtechnique", sa.Boolean, server_default="false"),
    )
    op.create_index(
        "idx_mitre_techniques_tactic", "mitre_techniques", ["tactic"]
    )
    op.create_index(
        "idx_mitre_techniques_name", "mitre_techniques", ["name"]
    )

    # MITRE ATT&CK tactics
    op.create_table(
        "mitre_tactics",
        sa.Column("id", sa.String(10), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("shortname", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("ordinal", sa.Integer, nullable=False),
    )
    op.create_index(
        "idx_mitre_tactics_ordinal", "mitre_tactics", ["ordinal"]
    )

    # MITRE ATT&CK threat groups
    op.create_table(
        "mitre_groups",
        sa.Column("id", sa.String(10), primary_key=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("aliases", JSONB, server_default="[]"),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("technique_ids", JSONB, server_default="[]"),
    )
    op.create_index(
        "idx_mitre_groups_name", "mitre_groups", ["name"]
    )

    # MITRE technique tags (entity <-> technique associations)
    op.create_table(
        "mitre_technique_tags",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column(
            "technique_id",
            sa.String(20),
            sa.ForeignKey("mitre_techniques.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float, server_default="0.5"),
        sa.Column("tagged_by", sa.String(200), server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_mitre_tags_technique", "mitre_technique_tags", ["technique_id"]
    )
    op.create_index(
        "idx_mitre_tags_entity",
        "mitre_technique_tags",
        ["entity_type", "entity_id"],
    )
    op.create_index(
        "idx_mitre_tags_tagged_by", "mitre_technique_tags", ["tagged_by"]
    )


def downgrade() -> None:
    op.drop_table("mitre_technique_tags")
    op.drop_table("mitre_groups")
    op.drop_table("mitre_tactics")
    op.drop_table("mitre_techniques")
