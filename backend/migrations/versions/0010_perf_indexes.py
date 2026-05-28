"""Add hot-path composite indexes for list endpoints (#146 perf).

Targeted, query-matched indexes for the two busiest list endpoints — the
investigation list and the IOC list/search. Each composite covers the
WHERE-filter column *and* the ORDER BY column so Postgres can satisfy
filter + sort from a single index scan instead of a filter scan + sort:

* ``idx_investigations_org_created`` — ``list_investigations`` filters on
  ``org_id`` and sorts ``created_at DESC``. The pre-existing single-column
  ``idx_investigations_created`` / ``idx_investigations_org_id`` indexes
  can't serve both at once.
* ``idx_investigations_assigned_to`` — plain ``analyst`` callers add a
  ``WHERE assigned_to = :uid`` predicate that had no supporting index.
* ``idx_iocs_investigation_first_seen`` — ``list_iocs`` /
  ``search_cross_investigation`` filter on ``investigation_id`` (or
  ``investigation_id IN (...)``) and sort ``first_seen DESC NULLS LAST``.

No table or column changes — indexes only, so this is behaviour-preserving.

Revision ID: 0010_perf_indexes
Revises: 0009_behavioral
Create Date: 2026-05-28
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010_perf_indexes"
down_revision: str | None = "0009_behavioral"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # investigations: org_id filter + created_at DESC sort (list_investigations)
    op.create_index(
        "idx_investigations_org_created",
        "investigations",
        ["org_id", "created_at"],
    )
    # investigations: plain-analyst ownership filter (WHERE assigned_to = :uid)
    op.create_index(
        "idx_investigations_assigned_to",
        "investigations",
        ["assigned_to"],
    )
    # iocs: investigation_id filter + first_seen DESC sort (list_iocs / search)
    op.create_index(
        "idx_iocs_investigation_first_seen",
        "iocs",
        ["investigation_id", "first_seen"],
    )


def downgrade() -> None:
    op.drop_index("idx_iocs_investigation_first_seen", table_name="iocs")
    op.drop_index("idx_investigations_assigned_to", table_name="investigations")
    op.drop_index("idx_investigations_org_created", table_name="investigations")
