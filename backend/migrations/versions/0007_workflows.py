"""Add workflows + workflow_versions tables (Phase 2 v1).

The Redesign Phase 2 milestone introduces the workflow as a first-class,
persistable artifact:

* ``workflows`` — the workflow's stable identity: name, description,
  ownership, org-scoping. One row per logical workflow.
* ``workflow_versions`` — the actual definition (engine Workflow JSON
  serialised to JSONB), with a published-state lifecycle:
  ``draft`` → ``published`` → ``deprecated``. Multiple versions per
  workflow; exactly one row per ``(workflow_id, version_number)``.

Both tables carry ``org_id`` (FK → ``organizations``) so the audit
finding wave-2 tenancy scoping extends to the new tables from day one
instead of requiring a retrofit migration later.

Revision ID: 0007_workflows
Revises: 0006_org_scoping
Create Date: 2026-05-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0007_workflows"
down_revision: str | None = "0006_org_scoping"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # workflows --------------------------------------------------------------
    op.create_table(
        "workflows",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
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
    op.create_index("idx_workflows_org_id", "workflows", ["org_id"])
    op.create_index("idx_workflows_created_at", "workflows", ["created_at"])

    # workflow_versions ------------------------------------------------------
    op.create_table(
        "workflow_versions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(64),
            sa.ForeignKey("workflows.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer, nullable=False),
        # state ∈ {"draft", "published", "deprecated"}.  Validated at the
        # service layer, not at the DB level, so a future state addition
        # (e.g. ``"rolled_back"``) doesn't need a destructive migration.
        sa.Column("state", sa.String(20), nullable=False, server_default="draft"),
        # Engine ``Workflow`` Pydantic model, ``.model_dump()``-ed.
        sa.Column("definition", JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_wfv_workflow_id", "workflow_versions", ["workflow_id"])
    op.create_index("idx_wfv_org_id", "workflow_versions", ["org_id"])
    op.create_index("idx_wfv_state", "workflow_versions", ["state"])
    # One row per (workflow, version_number). The version_number is
    # service-assigned (next-int after the current max for this workflow),
    # so the constraint enforces it instead of relying on caller
    # coordination.
    op.create_unique_constraint(
        "uq_wfv_workflow_version",
        "workflow_versions",
        ["workflow_id", "version_number"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_wfv_workflow_version", "workflow_versions", type_="unique")
    op.drop_index("idx_wfv_state", table_name="workflow_versions")
    op.drop_index("idx_wfv_org_id", table_name="workflow_versions")
    op.drop_index("idx_wfv_workflow_id", table_name="workflow_versions")
    op.drop_table("workflow_versions")

    op.drop_index("idx_workflows_created_at", table_name="workflows")
    op.drop_index("idx_workflows_org_id", table_name="workflows")
    op.drop_table("workflows")
