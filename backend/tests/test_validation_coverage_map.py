"""Detection-coverage map tests (#118 Phase C).

Covers :func:`validation_coverage_service.build_coverage_map`, which derives
``last_validated`` per technique from the EXISTING ``detection_validation_runs``
rows (no schema change) and flags techniques validated >N days ago OR never
validated as stale:

* last_validated is the max run ``generated_at`` over the runs that exercised a
  technique with a non-errored verdict (errored verdicts don't count);
* techniques with a detection proposal but no validation surface as
  never-validated / stale;
* the ``only_stale`` filter returns just the >Nd/never techniques;
* everything is org-scoped.

Isolation: every test seeds a dedicated per-test org via ``generate_id("org")``.
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services.validation_coverage_service import build_coverage_map

_NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)


async def _make_org(db) -> str:
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name=f"coverage-{org_id}"))
    await db.flush()
    return org_id


async def _persist_run(
    db,
    org_id: str,
    techniques: list[str],
    *,
    generated_at: datetime,
    verdicts: list[tuple[str, str]] | None = None,
) -> None:
    """Insert a validation-run row directly (bypassing feedback dispatch)."""
    row = DetectionValidationRunRow(
        id=generate_id("dvr"),
        org_id=org_id,
        run_id=generate_id("valrun"),
        packs=[],
        scenarios_run=1,
        total_techniques=len(techniques),
        detected_pct=0.0,
        gaps=[],
        coverage_by_technique=[{"technique_id": t} for t in techniques],
        emulated=bool(verdicts),
        target_env="sandbox" if verdicts else None,
        verdicts=[{"technique_id": t, "verdict": v} for (t, v) in (verdicts or [])],
        generated_at=generated_at,
    )
    db.add(row)
    await db.flush()


async def _seed_proposal(db, org_id: str, techniques: list[str]) -> None:
    db.add(
        DetectionProposalRow(
            id=generate_id("dprop"),
            org_id=org_id,
            proposal_id=f"p-{techniques[0]}",
            source_stix_id=f"src-{techniques[0]}",
            title="seed",
            sigma_yaml="title: seed\n",
            technique_ids=list(techniques),
            confidence=0.5,
            state="proposed",
        )
    )
    await db.flush()


async def test_coverage_map_reports_last_validated_and_flags_stale(db_session):
    org_id = await _make_org(db_session)
    # Recently validated (10 days ago) — fresh.
    await _persist_run(
        db_session,
        org_id,
        ["T1059"],
        generated_at=_NOW - timedelta(days=10),
        verdicts=[("T1059", "validated")],
    )
    # Validated 100 days ago — stale (>90d).
    await _persist_run(
        db_session,
        org_id,
        ["T1053"],
        generated_at=_NOW - timedelta(days=100),
        verdicts=[("T1053", "late")],
    )
    # Detection proposal but never validated — stale (never).
    await _seed_proposal(db_session, org_id, ["T1003"])

    entries = await build_coverage_map(db_session, org_id=org_id, stale_days=90, now=_NOW)
    by = {e.technique_id: e for e in entries}

    assert by["T1059"].stale is False
    assert by["T1059"].days_since_validated == 10
    assert by["T1059"].last_verdict == "validated"

    assert by["T1053"].stale is True
    assert by["T1053"].days_since_validated == 100
    assert by["T1053"].last_verdict == "late"

    assert by["T1003"].last_validated is None
    assert by["T1003"].days_since_validated is None
    assert by["T1003"].stale is True
    assert by["T1003"].has_detection is True


async def test_coverage_map_uses_latest_run_per_technique(db_session):
    org_id = await _make_org(db_session)
    # Two runs for the same technique — the newer (fresh) one must win.
    await _persist_run(
        db_session,
        org_id,
        ["T1105"],
        generated_at=_NOW - timedelta(days=200),
        verdicts=[("T1105", "silent_gap")],
    )
    await _persist_run(
        db_session,
        org_id,
        ["T1105"],
        generated_at=_NOW - timedelta(days=5),
        verdicts=[("T1105", "validated")],
    )
    entries = await build_coverage_map(db_session, org_id=org_id, now=_NOW)
    entry = next(e for e in entries if e.technique_id == "T1105")
    assert entry.days_since_validated == 5
    assert entry.last_verdict == "validated"
    assert entry.stale is False


async def test_coverage_map_errored_verdict_does_not_count_as_validated(db_session):
    org_id = await _make_org(db_session)
    # T1 scored errored (unscored) and also has a detection → must read as never
    # validated. T2 scored validated in the same run → fresh.
    await _persist_run(
        db_session,
        org_id,
        ["T1", "T2"],
        generated_at=_NOW - timedelta(days=5),
        verdicts=[("T1", "errored"), ("T2", "validated")],
    )
    await _seed_proposal(db_session, org_id, ["T1"])

    entries = await build_coverage_map(db_session, org_id=org_id, now=_NOW)
    by = {e.technique_id: e for e in entries}
    assert by["T1"].last_validated is None
    assert by["T1"].stale is True
    assert by["T2"].stale is False


async def test_coverage_map_counts_replay_runs_as_validated(db_session):
    org_id = await _make_org(db_session)
    # Pure in-process replay run (no verdicts) still exercised the technique.
    await _persist_run(
        db_session,
        org_id,
        ["T1136"],
        generated_at=_NOW - timedelta(days=3),
        verdicts=None,
    )
    entries = await build_coverage_map(db_session, org_id=org_id, now=_NOW)
    entry = next(e for e in entries if e.technique_id == "T1136")
    assert entry.days_since_validated == 3
    assert entry.stale is False
    assert entry.last_verdict is None


async def test_coverage_map_only_stale_filter(db_session):
    org_id = await _make_org(db_session)
    await _persist_run(
        db_session,
        org_id,
        ["T1059"],
        generated_at=_NOW - timedelta(days=10),
        verdicts=[("T1059", "validated")],
    )
    await _persist_run(
        db_session,
        org_id,
        ["T1053"],
        generated_at=_NOW - timedelta(days=120),
        verdicts=[("T1053", "validated")],
    )
    await _seed_proposal(db_session, org_id, ["T1003"])

    stale = await build_coverage_map(
        db_session, org_id=org_id, stale_days=90, only_stale=True, now=_NOW
    )
    ids = {e.technique_id for e in stale}
    assert "T1053" in ids  # 120d
    assert "T1003" in ids  # never
    assert "T1059" not in ids  # fresh
    assert all(e.stale for e in stale)


async def test_coverage_map_is_org_scoped(db_session):
    org_a = await _make_org(db_session)
    org_b = await _make_org(db_session)
    await _persist_run(
        db_session,
        org_a,
        ["T1059"],
        generated_at=_NOW - timedelta(days=5),
        verdicts=[("T1059", "validated")],
    )
    # org_b has no runs and no proposals → empty map.
    assert await build_coverage_map(db_session, org_id=org_b, now=_NOW) == []
    # org_a sees only its own technique.
    a_ids = {e.technique_id for e in await build_coverage_map(db_session, org_id=org_a, now=_NOW)}
    assert a_ids == {"T1059"}


async def test_coverage_map_empty_when_nothing_seeded(db_session):
    org_id = await _make_org(db_session)
    assert await build_coverage_map(db_session, org_id=org_id, now=_NOW) == []


async def test_coverage_map_stale_entries_sorted_first(db_session):
    org_id = await _make_org(db_session)
    await _persist_run(
        db_session,
        org_id,
        ["T1059"],
        generated_at=_NOW - timedelta(days=2),
        verdicts=[("T1059", "validated")],
    )
    await _seed_proposal(db_session, org_id, ["T1003"])  # never validated → stale
    entries = await build_coverage_map(db_session, org_id=org_id, now=_NOW)
    # Stale techniques sort ahead of fresh ones.
    assert entries[0].stale is True
    assert entries[-1].stale is False


async def test_dedicated_org_never_default(db_session):
    # Guard: the shared-DB isolation rule — count-sensitive seeding must use a
    # generated org id, never DEFAULT_ORG_ID.
    from btagent_backend.db.models import DEFAULT_ORG_ID

    org_id = await _make_org(db_session)
    assert org_id != DEFAULT_ORG_ID
    total = int(
        (
            await db_session.execute(
                select(func.count())
                .select_from(DetectionValidationRunRow)
                .where(DetectionValidationRunRow.org_id == org_id)
            )
        ).scalar_one()
    )
    assert total == 0
