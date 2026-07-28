"""Add draft-edit + PR-outcome columns to ``detection_proposals`` (#113 Phase C).

Two additive columns close the CTI → Detection loop:

* ``final_sigma_yaml`` — the analyst-edited "final" rule body produced when a
  proposal is selected and edited via the Engineer UI. NULL until an edit
  lands; when set, the row's ``state`` is ``modified`` and the composer ships
  this body (cited as *edited from draft*) instead of the generated draft.
* ``pr_outcome`` — where the rule sits in the detection-repo lifecycle
  (``proposed`` → ``pr_opened`` → ``merged`` / ``rejected``). Set to
  ``pr_opened`` when the mock Git PR is composed; a merge outcome recorded via
  the closed-loop endpoint flips it to ``merged`` and auto-installs the rule as
  a #112 hunt-pack entry plus a #118 sandbox detection-validation run.

Additive + fully reversible. Existing rows default to
``final_sigma_yaml=NULL`` / ``pr_outcome='proposed'`` — no backfill needed.

Revision ID: 0058_cti_edit_outcome
Revises: 0057_detection_emulation
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0058_cti_edit_outcome"
down_revision: str | None = "0057_detection_emulation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "detection_proposals",
        sa.Column("final_sigma_yaml", sa.Text(), nullable=True),
    )
    op.add_column(
        "detection_proposals",
        sa.Column(
            "pr_outcome",
            sa.String(length=16),
            nullable=False,
            server_default="proposed",
        ),
    )


def downgrade() -> None:
    op.drop_column("detection_proposals", "pr_outcome")
    op.drop_column("detection_proposals", "final_sigma_yaml")
