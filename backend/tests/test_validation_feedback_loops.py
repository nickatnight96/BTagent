"""Phase-C closed-loop feedback tests (#118).

Covers the two feedback loops fired off a scored detection-validation run and
the dispatcher wired into the completion path:

* (A) ``silent_gap`` → exactly one #113 detection proposal, idempotent on re-run.
* (B) ``late`` / ``wrong_severity`` → a #112 hunt-pack tuning suggestion
  capturing the offending rule + observed-vs-expected latency/severity,
  idempotent per (org, technique).
* the dispatcher routes each verdict to the right loop (and files nothing for
  ``validated`` / ``errored``), is org-scoped, and is best-effort — a feedback
  failure never sinks the persisted run.

Isolation: the backend suite shares one in-memory SQLite; every count-sensitive
assertion seeds and queries a dedicated per-test org via ``generate_id("org")``,
never ``DEFAULT_ORG_ID``.
"""

import json
from datetime import UTC, datetime

from btagent_shared.types.detection_validation import (
    CoverageDelta,
    CoverageResult,
    Emulator,
    RuleFiring,
    TargetEnv,
    TechniqueVerdict,
    ValidationReport,
    ValidationSummary,
    ValidationVerdict,
)
from btagent_shared.types.enums import Severity
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_pattern import HuntPackSuggestionRow, PatternHuntProposalRow
from btagent_backend.services import validation_run_service
from btagent_backend.services.validation_feedback_service import (
    dispatch_validation_feedback,
    file_silent_gap_proposal,
    file_tuning_suggestion,
)


async def _make_org(db) -> str:
    """Seed a dedicated org and return its id (never DEFAULT_ORG_ID)."""
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name=f"feedback-{org_id}"))
    await db.flush()
    return org_id


def _verdict(
    technique_id: str,
    verdict: ValidationVerdict,
    *,
    fired: list[RuleFiring] | None = None,
    observed_severity: Severity | None = None,
    latency_seconds: float | None = None,
) -> TechniqueVerdict:
    return TechniqueVerdict(
        technique_id=technique_id,
        verdict=verdict,
        emulator=Emulator.ATOMIC_RED_TEAM,
        expected_severity=Severity.HIGH,
        observed_severity=observed_severity,
        latency_seconds=latency_seconds,
        latency_sla_seconds=300.0,
        fired_rules=fired or [],
        coverage_delta=CoverageDelta(technique_id=technique_id),
        detail="",
    )


def _report(verdicts: list[TechniqueVerdict], run_id: str = "valrun_FBTEST") -> ValidationReport:
    coverage = [
        CoverageResult(
            technique_id=v.technique_id,
            total_simulated=1,
            detected=1 if v.verdict == ValidationVerdict.VALIDATED else 0,
            missed=0 if v.verdict == ValidationVerdict.VALIDATED else 1,
        )
        for v in verdicts
    ]
    return ValidationReport(
        run_id=run_id,
        scenarios_run=len(verdicts),
        coverage_by_technique=coverage,
        summary=ValidationSummary(detected_pct=0.0, total_techniques=len(coverage), gaps=[]),
        generated_at=datetime.now(UTC),
        emulation_target_env=TargetEnv.SANDBOX,
        verdicts=verdicts,
    )


async def _count_proposals(db, org_id: str) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(DetectionProposalRow)
                .where(DetectionProposalRow.org_id == org_id)
            )
        ).scalar_one()
    )


async def _count_suggestions(db, org_id: str) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(HuntPackSuggestionRow)
                .where(HuntPackSuggestionRow.org_id == org_id)
            )
        ).scalar_one()
    )


# --------------------------------------------------------------------------- #
# (A) silent_gap → #113
# --------------------------------------------------------------------------- #


async def test_silent_gap_files_exactly_one_proposal_idempotent(db_session):
    org_id = await _make_org(db_session)

    await file_silent_gap_proposal(db_session, org_id=org_id, technique_id="T1059.001")
    rows = (
        (
            await db_session.execute(
                select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.technique_ids == ["T1059.001"]
    assert row.source_stix_id == "validation-gap--T1059.001"
    assert row.state == "proposed"
    assert "silent gap" in row.title.lower()

    # Re-scoring the same gap upserts in place — still exactly one row.
    await file_silent_gap_proposal(db_session, org_id=org_id, technique_id="T1059.001")
    assert await _count_proposals(db_session, org_id) == 1


async def test_silent_gap_does_not_clobber_analyst_decision(db_session):
    org_id = await _make_org(db_session)
    await file_silent_gap_proposal(db_session, org_id=org_id, technique_id="T1003")
    row = (
        await db_session.execute(
            select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
        )
    ).scalar_one()
    # Analyst accepts the draft.
    row.state = "accepted"
    await db_session.flush()

    # A re-scored gap must NOT revert the decision (persist_proposals upsert
    # leaves decided rows untouched).
    await file_silent_gap_proposal(db_session, org_id=org_id, technique_id="T1003")
    refreshed = (
        await db_session.execute(
            select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
        )
    ).scalar_one()
    assert refreshed.state == "accepted"


# --------------------------------------------------------------------------- #
# (B) late / wrong_severity → #112 tuning suggestion
# --------------------------------------------------------------------------- #


async def test_late_files_tuning_suggestion_with_latency_and_rule(db_session):
    org_id = await _make_org(db_session)
    fired = [
        RuleFiring(
            rule_id="rule-ps-encoded",
            rule_title="Suspicious Encoded PowerShell",
            technique_id="T1059.001",
            severity=Severity.MEDIUM,
            latency_seconds=600.0,
        )
    ]
    verdict = _verdict(
        "T1059.001",
        ValidationVerdict.LATE,
        fired=fired,
        observed_severity=Severity.MEDIUM,
        latency_seconds=600.0,
    )

    await file_tuning_suggestion(db_session, org_id=org_id, verdict=verdict, plan_id="valrun_1")

    suggestions = (
        (
            await db_session.execute(
                select(HuntPackSuggestionRow).where(HuntPackSuggestionRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(suggestions) == 1
    sugg = suggestions[0]
    assert sugg.technique_ids == ["T1059.001"]
    assert sugg.state == "suggested"
    # The offending rule + observed-vs-expected latency/severity are captured.
    assert "rule-ps-encoded" in json.dumps(sugg.manifest)
    assert "600" in sugg.rationale  # observed latency
    assert "late" in sugg.rationale

    # A deterministic dismissed shadow parent anchors the FK (migration-free).
    shadows = (
        (
            await db_session.execute(
                select(PatternHuntProposalRow).where(PatternHuntProposalRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(shadows) == 1
    assert shadows[0].state == "dismissed"
    assert shadows[0].cluster_id == "detection-tuning:T1059.001"


async def test_wrong_severity_files_tuning_suggestion(db_session):
    org_id = await _make_org(db_session)
    verdict = _verdict(
        "T1055",
        ValidationVerdict.WRONG_SEVERITY,
        fired=[RuleFiring(rule_id="rule-inject", technique_id="T1055", severity=Severity.LOW)],
        observed_severity=Severity.LOW,
    )
    await file_tuning_suggestion(db_session, org_id=org_id, verdict=verdict)
    assert await _count_suggestions(db_session, org_id) == 1


async def test_tuning_suggestion_idempotent_bumps_hit_count(db_session):
    org_id = await _make_org(db_session)
    verdict = _verdict(
        "T1053",
        ValidationVerdict.LATE,
        fired=[RuleFiring(rule_id="rule-sched", technique_id="T1053")],
        latency_seconds=450.0,
    )
    await file_tuning_suggestion(db_session, org_id=org_id, verdict=verdict)
    await file_tuning_suggestion(db_session, org_id=org_id, verdict=verdict)

    assert await _count_suggestions(db_session, org_id) == 1
    # And only one shadow parent (idempotent per (org, technique)).
    shadow_count = int(
        (
            await db_session.execute(
                select(func.count())
                .select_from(PatternHuntProposalRow)
                .where(PatternHuntProposalRow.org_id == org_id)
            )
        ).scalar_one()
    )
    assert shadow_count == 1
    row = (
        await db_session.execute(
            select(HuntPackSuggestionRow).where(HuntPackSuggestionRow.org_id == org_id)
        )
    ).scalar_one()
    assert row.hit_count == 2


async def test_tuning_suggestion_keeps_analyst_decision(db_session):
    org_id = await _make_org(db_session)
    verdict = _verdict(
        "T1105",
        ValidationVerdict.LATE,
        fired=[RuleFiring(rule_id="rule-dl", technique_id="T1105")],
    )
    row = await file_tuning_suggestion(db_session, org_id=org_id, verdict=verdict)
    row.state = "dismissed"
    await db_session.flush()

    # Re-scoring bumps hit_count but never resurrects a dismissed suggestion.
    await file_tuning_suggestion(db_session, org_id=org_id, verdict=verdict)
    refreshed = (
        await db_session.execute(
            select(HuntPackSuggestionRow).where(HuntPackSuggestionRow.org_id == org_id)
        )
    ).scalar_one()
    assert refreshed.state == "dismissed"
    assert refreshed.hit_count == 2


# --------------------------------------------------------------------------- #
# Dispatcher — routing, org-scope, best-effort
# --------------------------------------------------------------------------- #


async def test_dispatch_routes_each_verdict_to_its_loop(db_session):
    org_id = await _make_org(db_session)
    verdicts = [
        _verdict("T1001", ValidationVerdict.SILENT_GAP),
        _verdict(
            "T1002",
            ValidationVerdict.LATE,
            fired=[RuleFiring(rule_id="r2", technique_id="T1002")],
        ),
        _verdict(
            "T1003",
            ValidationVerdict.WRONG_SEVERITY,
            fired=[RuleFiring(rule_id="r3", technique_id="T1003")],
        ),
        _verdict("T1004", ValidationVerdict.VALIDATED),
        _verdict("T1005", ValidationVerdict.ERRORED),
    ]

    filed = await dispatch_validation_feedback(db_session, org_id=org_id, report=_report(verdicts))
    assert filed == {"silent_gap": 1, "tuning": 2}
    # T1001 → one #113 proposal; T1002/T1003 → two #112 suggestions.
    assert await _count_proposals(db_session, org_id) == 1
    assert await _count_suggestions(db_session, org_id) == 2
    # validated/errored produced nothing.


async def test_dispatch_is_org_scoped(db_session):
    org_a = await _make_org(db_session)
    org_b = await _make_org(db_session)
    await dispatch_validation_feedback(
        db_session,
        org_id=org_a,
        report=_report([_verdict("T1059", ValidationVerdict.SILENT_GAP)]),
    )
    assert await _count_proposals(db_session, org_a) == 1
    assert await _count_proposals(db_session, org_b) == 0


async def test_replay_report_without_verdicts_is_noop(db_session):
    org_id = await _make_org(db_session)
    report = _report([])  # no verdicts (pure in-process replay)
    filed = await dispatch_validation_feedback(db_session, org_id=org_id, report=report)
    assert filed == {"silent_gap": 0, "tuning": 0}
    assert await _count_proposals(db_session, org_id) == 0
    assert await _count_suggestions(db_session, org_id) == 0


# --------------------------------------------------------------------------- #
# Completion-path wiring — persist_validation_report fires + survives failure
# --------------------------------------------------------------------------- #


async def test_persist_validation_report_default_dispatch_files_feedback(db_session):
    org_id = await _make_org(db_session)
    report = _report([_verdict("T1070", ValidationVerdict.SILENT_GAP)], run_id="valrun_WIRED")
    row = await validation_run_service.persist_validation_report(db_session, report, org_id=org_id)
    assert row.run_id == "valrun_WIRED"
    # The wired-in default dispatcher filed the #113 proposal.
    assert await _count_proposals(db_session, org_id) == 1


async def test_persist_validation_report_survives_feedback_failure(db_session):
    org_id = await _make_org(db_session)

    async def _boom(db, **kwargs):
        raise RuntimeError("feedback exploded")

    report = _report([_verdict("T1059", ValidationVerdict.SILENT_GAP)], run_id="valrun_BOOM")
    # Best-effort: the raising hook is swallowed and the run row still persists.
    row = await validation_run_service.persist_validation_report(
        db_session, report, org_id=org_id, feedback_dispatch=_boom
    )
    assert row.id.startswith("dvr_")
    assert row.run_id == "valrun_BOOM"
    # The failing hook filed nothing.
    assert await _count_proposals(db_session, org_id) == 0


async def test_persist_validation_report_injected_spy_is_called(db_session):
    org_id = await _make_org(db_session)
    seen: dict[str, object] = {}

    async def _spy(db, *, org_id, report):
        seen["org_id"] = org_id
        seen["run_id"] = report.run_id

    report = _report([_verdict("T1078", ValidationVerdict.LATE)], run_id="valrun_SPY")
    await validation_run_service.persist_validation_report(
        db_session, report, org_id=org_id, feedback_dispatch=_spy
    )
    assert seen == {"org_id": org_id, "run_id": "valrun_SPY"}
