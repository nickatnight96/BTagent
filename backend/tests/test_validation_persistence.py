"""Tests for detection-validation run persistence (#118).

Covers the ``persist_validation_report`` writer that lands a ``ValidationReport``
in the ``detection_validation_runs`` history table: the summary pivots are
denormalised into columns, the full per-technique payload rides in JSONB, and
the writer does not commit (the caller owns that).
"""

from datetime import UTC, datetime

from btagent_shared.types.detection_validation import (
    CoverageResult,
    ValidationReport,
    ValidationSummary,
)
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services import validation_run_service as svc

_GEN_AT = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


def _report() -> ValidationReport:
    return ValidationReport(
        run_id="valrun_TESTREPORT",
        scenarios_run=2,
        coverage_by_technique=[
            CoverageResult(
                technique_id="T1059",
                total_simulated=3,
                detected=2,
                missed=1,
                false_positives=0,
                rules_fired=["rule-a"],
                rules_expected_but_missed=["rule-b"],
            ),
            CoverageResult(
                technique_id="T1053",
                total_simulated=1,
                detected=1,
                missed=0,
            ),
        ],
        summary=ValidationSummary(
            detected_pct=75.0,
            total_techniques=2,
            gaps=["T1059"],
        ),
        generated_at=_GEN_AT,
    )


async def test_persist_lands_row_with_denormalised_pivots(db_session):
    row = await svc.persist_validation_report(
        db_session, _report(), org_id=DEFAULT_ORG_ID, packs=["windows_baseline"]
    )
    assert row.id.startswith("dvr_")
    assert row.run_id == "valrun_TESTREPORT"
    assert row.scenarios_run == 2
    assert row.total_techniques == 2
    assert row.detected_pct == 75.0
    assert row.gaps == ["T1059"]
    assert row.packs == ["windows_baseline"]
    assert row.generated_at == _GEN_AT

    # The full per-technique payload is stored verbatim.
    assert len(row.coverage_by_technique) == 2
    by_tech = {c["technique_id"]: c for c in row.coverage_by_technique}
    assert by_tech["T1059"]["detected"] == 2
    assert by_tech["T1059"]["missed"] == 1
    assert by_tech["T1059"]["rules_expected_but_missed"] == ["rule-b"]


async def test_persist_is_queryable_and_org_scoped(db_session):
    await svc.persist_validation_report(db_session, _report(), org_id=DEFAULT_ORG_ID)
    rows = (
        (
            await db_session.execute(
                select(DetectionValidationRunRow).where(
                    DetectionValidationRunRow.org_id == DEFAULT_ORG_ID,
                    DetectionValidationRunRow.run_id == "valrun_TESTREPORT",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].packs == []  # default when no packs supplied


async def test_persist_does_not_commit(db_session):
    # The writer flushes (so the row is visible in-session) but must not commit;
    # a rollback afterwards discards it.
    await svc.persist_validation_report(db_session, _report(), org_id=DEFAULT_ORG_ID)
    await db_session.rollback()
    rows = (
        (
            await db_session.execute(
                select(DetectionValidationRunRow).where(
                    DetectionValidationRunRow.org_id == DEFAULT_ORG_ID
                )
            )
        )
        .scalars()
        .all()
    )
    assert rows == []
