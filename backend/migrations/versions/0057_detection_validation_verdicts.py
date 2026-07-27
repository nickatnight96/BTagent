"""Add emulation columns to ``detection_validation_runs`` (#118 foundation).

The detection-validation feature gains a sandbox-gated adversary-emulation path
(Atomic Red Team / MITRE Caldera, mock-first) alongside the existing in-process
pySigma replay. A run that went through an emulator records:

* ``emulated`` — whether this run fired through an emulator (vs. pure replay).
* ``target_env`` — the approved SANDBOX the emulation ran in (the sandbox-
  enforcement layer guarantees this is only ever an approved sandbox).
* ``verdicts`` — the per-technique scored verdicts (validated / wrong_severity /
  late / silent_gap / errored).

Additive + fully reversible. Existing replay rows default to
``emulated=false`` / ``target_env=NULL`` / ``verdicts=[]`` — no backfill needed.

Revision ID: 0057_detection_validation_verdicts
Revises: 0056_response_safelist
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0057_detection_validation_verdicts"
down_revision: str | None = "0056_response_safelist"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "detection_validation_runs",
        sa.Column("emulated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "detection_validation_runs",
        sa.Column("target_env", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "detection_validation_runs",
        sa.Column("verdicts", JSONB, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("detection_validation_runs", "verdicts")
    op.drop_column("detection_validation_runs", "target_env")
    op.drop_column("detection_validation_runs", "emulated")
