"""Hunt triage composite indexes (#119 Phase A).

The hunt-finding store landed in ``0008_hunt_findings`` with single-column
indexes only. The triage inbox's hot paths all filter on ``org_id`` and
either sort by ``created_at`` (cluster/finding listing) or filter by
``state`` (default inbox hides ``suppressed``), so — following the
``0010_perf_indexes`` precedent — each composite covers the WHERE-filter
column *and* the ORDER BY / second-filter column so Postgres can satisfy
both from a single index scan:

* ``idx_hunt_findings_org_created`` — org filter + created_at sort.
* ``idx_hunt_findings_org_state``  — org filter + state filter.

The now-redundant single-column ``idx_hunt_findings_org_id`` is dropped
(it is a left-prefix of both composites). No table or column changes —
indexes only, so this is behaviour-preserving.

Revision ID: 0020_hunt_triage_indexes
Revises: 0019_workflow_soft_delete
Create Date: 2026-06-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0020_hunt_triage_indexes"
down_revision: str | None = "0019_workflow_soft_delete"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "idx_hunt_findings_org_created",
        "hunt_findings",
        ["org_id", "created_at"],
    )
    op.create_index(
        "idx_hunt_findings_org_state",
        "hunt_findings",
        ["org_id", "state"],
    )
    op.drop_index("idx_hunt_findings_org_id", table_name="hunt_findings")


def downgrade() -> None:
    op.create_index("idx_hunt_findings_org_id", "hunt_findings", ["org_id"])
    op.drop_index("idx_hunt_findings_org_state", table_name="hunt_findings")
    op.drop_index("idx_hunt_findings_org_created", table_name="hunt_findings")
