"""Coverage Console aggregation tests (#501).

The console composes four already-shipped surfaces into one payload; these
tests pin the *composition*, not the underlying services (which have their own
suites):

* technique coverage + validation freshness land in the right heatmap band
  (fresh / stale / never / silent_gap), with silent_gap beating staleness;
* rule health reproduces the #112 states (``errored`` / ``over_firing`` /
  ``under_firing``) and *omits* healthy rules;
* a proposal whose telemetry validation could not run surfaces as a telemetry
  gap, while one that ran somewhere does not;
* the **persisted** DataSourceMatcher gap set (``data_source_gaps``, migration
  0066) is the primary signal and names the real OCSF classes, while a row
  predating the column still falls back to the older derived heuristic — the
  NULL-vs-``[]`` distinction must not collapse into "covered";
* verdict counts tally every kind across the run history;
* next-best-actions are ordered worst-first and deep-link to a real route;
* the empty org returns an honest empty payload rather than a broken one;
* everything is strictly org-scoped — org B never sees org A's coverage.

Isolation: every test seeds a dedicated per-test org via ``generate_id("org")``
(never ``DEFAULT_ORG_ID``), because the backend suite shares one session-scoped
in-memory SQLite database and committed rows persist across the run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_hunt import HuntPackRunRow
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services.coverage_console_service import (
    build_coverage_console,
    classify_rule_state,
    classify_status,
    classify_telemetry_gap,
    tally_verdicts,
)

_NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Seeding helpers — each takes an explicit org so scoping is never accidental.
# --------------------------------------------------------------------------- #


async def _make_org(db) -> str:
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name=f"console-{org_id}"))
    await db.flush()
    return org_id


async def _seed_run(
    db,
    org_id: str,
    *,
    generated_at: datetime,
    techniques: list[str] | None = None,
    verdicts: list[tuple[str, str]] | None = None,
) -> None:
    db.add(
        DetectionValidationRunRow(
            id=generate_id("dvr"),
            org_id=org_id,
            run_id=generate_id("valrun"),
            packs=[],
            scenarios_run=1,
            total_techniques=len(techniques or []),
            detected_pct=0.0,
            gaps=[],
            coverage_by_technique=[{"technique_id": t} for t in (techniques or [])],
            emulated=bool(verdicts),
            target_env="sandbox" if verdicts else None,
            verdicts=[{"technique_id": t, "verdict": v} for (t, v) in (verdicts or [])],
            generated_at=generated_at,
        )
    )
    await db.flush()


async def _seed_proposal(
    db,
    org_id: str,
    *,
    techniques: list[str],
    state: str = "proposed",
    validation: dict | None = None,
    pr_outcome: str = "proposed",
    data_source_gaps: list[str] | None = None,
    data_sources_required: list[str] | None = None,
) -> DetectionProposalRow:
    """Seed one proposal row.

    ``data_source_gaps`` defaults to ``None`` on purpose: that is a row written
    before migration 0066 (the matcher never ran for it), which is what the
    derived-fallback assertions need. Pass ``[]`` for "the matcher ran and found
    nothing missing" — a different claim entirely.
    """
    row = DetectionProposalRow(
        id=generate_id("dprop"),
        org_id=org_id,
        proposal_id=f"p-{techniques[0]}-{generate_id('x')}",
        source_stix_id=f"src-{generate_id('s')}",
        title=f"Detect {techniques[0]}",
        sigma_yaml="title: seed\n",
        technique_ids=list(techniques),
        confidence=0.5,
        state=state,
        validation=validation,
        pr_outcome=pr_outcome,
        data_source_gaps=data_source_gaps,
        data_sources_required=data_sources_required,
    )
    db.add(row)
    await db.flush()
    return row


async def _seed_pack_run(
    db,
    org_id: str,
    *,
    pack_id: str,
    rule_stats: dict,
    started_at: datetime,
    status: str = "completed",
) -> None:
    db.add(
        HuntPackRunRow(
            id=generate_id("hpr"),
            org_id=org_id,
            run_id=generate_id("hrun"),
            pack_id=pack_id,
            pack_name="Console pack",
            backends=["splunk"],
            rule_stats=rule_stats,
            hit_count=sum(int(v.get("hits", 0)) for v in rule_stats.values()),
            error_count=0,
            findings_created=0,
            status=status,
            started_at=started_at,
        )
    )
    await db.flush()


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_silent_gap_outranks_staleness_in_the_heatmap_band():
    # A technique that is both stale AND known to have gone silent must read as
    # the coverage hole it is, not as a mere "we haven't checked lately".
    assert (
        classify_status(
            stale=True,
            last_validated=_NOW - timedelta(days=400),
            last_verdict="silent_gap",
        )
        == "silent_gap"
    )
    assert classify_status(stale=True, last_validated=None, last_verdict=None) == "never"
    assert classify_status(stale=True, last_validated=_NOW, last_verdict="validated") == "stale"
    assert classify_status(stale=False, last_validated=_NOW, last_verdict="validated") == "fresh"


def test_rule_state_precedence_matches_the_huntpacks_view():
    # errored > over_firing > under_firing > healthy. A rule that both errored
    # and is a chronic hitter must not read as merely noisy.
    assert (
        classify_rule_state(last_errors=1, is_over_firing=True, runs_observed=5, total_hits=99)
        == "errored"
    )
    assert (
        classify_rule_state(last_errors=0, is_over_firing=True, runs_observed=5, total_hits=99)
        == "over_firing"
    )
    assert (
        classify_rule_state(last_errors=0, is_over_firing=False, runs_observed=3, total_hits=0)
        == "under_firing"
    )
    # Healthy rules are absent from the broken list entirely.
    assert (
        classify_rule_state(last_errors=0, is_over_firing=False, runs_observed=5, total_hits=4)
        is None
    )
    # Too few observations to call it silent — a new rule is not a broken rule.
    assert (
        classify_rule_state(last_errors=0, is_over_firing=False, runs_observed=2, total_hits=0)
        is None
    )


def test_verdict_tally_counts_every_kind_and_ignores_junk():
    counts = tally_verdicts(
        [
            [
                {"technique_id": "T1", "verdict": "validated"},
                {"technique_id": "T2", "verdict": "silent_gap"},
                {"technique_id": "T3", "verdict": "not_a_verdict"},
            ],
            [{"technique_id": "T4", "verdict": "late"}],
            None,
        ]
    )
    assert counts.validated == 1
    assert counts.silent_gap == 1
    assert counts.late == 1
    assert counts.wrong_severity == 0
    assert counts.errored == 0
    # The unknown label is not silently folded into a real bucket.
    assert counts.total == 3


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


async def test_console_bands_techniques_by_freshness(db_session):
    org_id = await _make_org(db_session)
    # Fresh: validated 5 days ago.
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=5),
        verdicts=[("T1059", "validated")],
    )
    # Stale: validated 200 days ago, passed at the time.
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=200),
        verdicts=[("T1055", "validated")],
    )
    # Proven silent gap 10 days ago — recent, but a real hole.
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=10),
        verdicts=[("T1003", "silent_gap")],
    )
    # Never validated: a proposal exists, no run ever exercised it.
    await _seed_proposal(db_session, org_id, techniques=["T1078"])

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    by_id = {c.technique_id: c for c in console.techniques}
    assert by_id["T1059"].status == "fresh"
    assert by_id["T1055"].status == "stale"
    assert by_id["T1003"].status == "silent_gap"
    assert by_id["T1078"].status == "never"
    assert by_id["T1078"].has_detection is True

    assert console.summary.total_techniques == 4
    assert console.summary.fresh == 1
    assert console.summary.stale == 1
    assert console.summary.silent_gap == 1
    assert console.summary.never_validated == 1
    assert console.stale_days == 90

    # Every technique lands in exactly one tactic column, and the column
    # tallies agree with the cells inside it.
    assert sum(len(col.techniques) for col in console.tactics) == 4
    for col in console.tactics:
        for band in ("fresh", "stale", "never", "silent_gap"):
            assert getattr(col, band) == sum(1 for c in col.techniques if c.status == band)


async def test_console_lists_broken_rules_and_omits_healthy_ones(db_session):
    org_id = await _make_org(db_session)
    pack_id = generate_id("pack")
    noisy = generate_id("rule")
    silent = generate_id("rule")
    healthy = generate_id("rule")
    broken = generate_id("rule")

    for day in range(4):
        await _seed_pack_run(
            db_session,
            org_id,
            pack_id=pack_id,
            started_at=_NOW - timedelta(days=day),
            rule_stats={
                # Hits on every run → over_firing via the noise baseline.
                noisy: {"title": "Chronic beacon", "hits": 9, "errors": 0},
                # Observed 4 runs, never hit → under_firing.
                silent: {"title": "Never fires", "hits": 0, "errors": 0},
                # Hits sometimes → healthy, must not appear.
                healthy: {"title": "Normal", "hits": 1 if day == 0 else 0, "errors": 0},
                # Latest run errored → errored (wins over everything else).
                broken: {
                    "title": "Broken query",
                    "hits": 3,
                    "errors": 1 if day == 0 else 0,
                },
            },
        )

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    states = {r.rule_id: r.state for r in console.broken_rules}
    assert states[noisy] == "over_firing"
    assert states[silent] == "under_firing"
    assert states[broken] == "errored"
    # A rule doing its job is not a finding.
    assert healthy not in states
    assert console.summary.broken_rules == 3
    # Errored first — a rule that cannot run is worse than one that runs loudly.
    assert console.broken_rules[0].state == "errored"


async def test_console_flags_detections_unproven_against_telemetry(db_session):
    org_id = await _make_org(db_session)
    # Every backend errored → the rule could not be run against telemetry.
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1566"],
        validation={
            "backends": [
                {"backend": "splunk", "error": "no such index"},
                {"backend": "sentinel", "error": "auth failed"},
            ]
        },
    )
    # Never validated at all.
    await _seed_proposal(db_session, org_id, techniques=["T1204"])
    # Ran fine somewhere → not a telemetry gap, even with one bad backend.
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1105"],
        validation={
            "backends": [
                {"backend": "splunk", "error": None, "hit_count": 4},
                {"backend": "sentinel", "error": "auth failed"},
            ]
        },
    )

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    gaps = {g.technique_id: g for g in console.telemetry_gaps}
    assert set(gaps) == {"T1566", "T1204"}
    assert gaps["T1566"].reason == "backends_errored"
    assert gaps["T1566"].unavailable_backends == ["sentinel", "splunk"]
    assert gaps["T1204"].reason == "never_validated"
    # A hard "the telemetry refused us" outranks "we never asked".
    assert console.telemetry_gaps[0].reason == "backends_errored"
    assert console.summary.telemetry_gaps == 2


async def test_console_prefers_the_persisted_ocsf_gap_over_the_derived_reason(db_session):
    org_id = await _make_org(db_session)
    # A row whose stored DataSourceMatcher result says the telemetry it needs is
    # emitted by nothing connected. It ALSO validated cleanly on one backend — so
    # under the old derived-only heuristic it would not be a gap at all.
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1114"],
        validation={"backends": [{"backend": "splunk", "error": None, "hit_count": 2}]},
        data_source_gaps=["email_activity"],
        data_sources_required=["splunk"],
    )

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    gaps = {g.technique_id: g for g in console.telemetry_gaps}
    assert set(gaps) == {"T1114"}
    gap = gaps["T1114"]
    # A rule that cannot fire is a gap even though a backend ran it — this is the
    # whole reason the matcher output had to be persisted.
    assert gap.reason == "ocsf_telemetry_gap"
    assert gap.signal == "persisted"
    # The real missing OCSF class is named, not merely implied.
    assert gap.missing_ocsf_classes == ["email_activity"]
    assert gap.data_sources_required == ["splunk"]
    assert console.summary.telemetry_gaps == 1
    assert console.summary.ocsf_telemetry_gaps == 1
    # The action names the missing telemetry rather than only "unproven".
    action = {a.id: a for a in console.next_best_actions}["nba_telemetry_gaps"]
    assert "email_activity" in action.detail


async def test_console_falls_back_to_the_derived_heuristic_for_legacy_rows(db_session):
    org_id = await _make_org(db_session)
    # Legacy row: data_source_gaps is NULL — the matcher never ran for it. The
    # pre-#501 behaviour must survive verbatim for these.
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1566"],
        validation={"backends": [{"backend": "splunk", "error": "no such index"}]},
    )
    await _seed_proposal(db_session, org_id, techniques=["T1204"])
    # A row the matcher DID run for and found nothing missing (``[]``, not NULL)
    # is still subject to the derived checks — an empty gap set is not a licence
    # to stop reporting "never proven".
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1105"],
        data_source_gaps=[],
        data_sources_required=["splunk"],
    )

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    gaps = {g.technique_id: g for g in console.telemetry_gaps}
    assert set(gaps) == {"T1566", "T1204", "T1105"}
    assert gaps["T1566"].reason == "backends_errored"
    assert gaps["T1204"].reason == "never_validated"
    assert gaps["T1105"].reason == "never_validated"
    # None of the three claims to be a measured OCSF gap.
    assert {g.signal for g in console.telemetry_gaps} == {"derived"}
    assert all(g.missing_ocsf_classes == [] for g in console.telemetry_gaps)
    assert console.summary.ocsf_telemetry_gaps == 0
    # A matched row still reports which connectors CAN feed it.
    assert gaps["T1105"].data_sources_required == ["splunk"]


async def test_persisted_ocsf_gap_outranks_the_derived_reasons_in_the_ordering(db_session):
    org_id = await _make_org(db_session)
    await _seed_proposal(db_session, org_id, techniques=["T1204"])
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1566"],
        validation={"backends": [{"backend": "splunk", "error": "auth failed"}]},
    )
    await _seed_proposal(
        db_session,
        org_id,
        techniques=["T1114"],
        data_source_gaps=["email_activity"],
    )

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    # Worst-first: cannot fire > no backend could run it > nobody has checked.
    assert [g.reason for g in console.telemetry_gaps] == [
        "ocsf_telemetry_gap",
        "backends_errored",
        "never_validated",
    ]


def test_a_gap_classification_never_turns_unknown_into_covered():
    # NULL (matcher never ran) + never validated → still a derived gap.
    assert classify_telemetry_gap(
        persisted_gaps=None, validation=None, unavailable_backends=[], available_backends=[]
    ) == ("never_validated", "derived")
    # [] (matcher ran, nothing missing) is NOT by itself a gap...
    assert (
        classify_telemetry_gap(
            persisted_gaps=[],
            validation={"backends": [{"backend": "splunk"}]},
            unavailable_backends=[],
            available_backends=["splunk"],
        )
        is None
    )
    # ...but it does not suppress the derived checks either.
    assert classify_telemetry_gap(
        persisted_gaps=[], validation=None, unavailable_backends=[], available_backends=[]
    ) == ("never_validated", "derived")
    # A real missing class wins over a clean validation run.
    assert classify_telemetry_gap(
        persisted_gaps=["email_activity"],
        validation={"backends": [{"backend": "splunk"}]},
        unavailable_backends=[],
        available_backends=["splunk"],
    ) == ("ocsf_telemetry_gap", "persisted")


async def test_persisted_gaps_are_org_scoped(db_session):
    org_a = await _make_org(db_session)
    org_b = await _make_org(db_session)
    await _seed_proposal(
        db_session,
        org_a,
        techniques=["T1114"],
        data_source_gaps=["email_activity"],
        data_sources_required=["splunk"],
    )

    console_a = await build_coverage_console(db_session, org_id=org_a, now=_NOW)
    console_b = await build_coverage_console(db_session, org_id=org_b, now=_NOW)

    assert [g.missing_ocsf_classes for g in console_a.telemetry_gaps] == [["email_activity"]]
    assert console_a.summary.ocsf_telemetry_gaps == 1
    # Org B must not learn anything about org A's telemetry posture.
    assert console_b.telemetry_gaps == []
    assert console_b.summary.ocsf_telemetry_gaps == 0
    assert console_b.summary.telemetry_gaps == 0


async def test_console_counts_verdicts_and_the_review_queue(db_session):
    org_id = await _make_org(db_session)
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=1),
        verdicts=[
            ("T1059", "validated"),
            ("T1055", "wrong_severity"),
            ("T1003", "silent_gap"),
        ],
    )
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=2),
        verdicts=[("T1078", "late"), ("T1105", "errored")],
    )
    await _seed_proposal(db_session, org_id, techniques=["T1566"], state="proposed")
    await _seed_proposal(
        db_session, org_id, techniques=["T1204"], state="accepted", pr_outcome="pr_opened"
    )

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    assert console.verdict_counts.validated == 1
    assert console.verdict_counts.wrong_severity == 1
    assert console.verdict_counts.silent_gap == 1
    assert console.verdict_counts.late == 1
    assert console.verdict_counts.errored == 1
    assert console.verdict_counts.total == 5

    assert console.summary.open_proposals == 2
    assert console.summary.proposals_awaiting_review == 1
    assert console.summary.prs_open == 1


async def test_next_best_actions_are_ordered_worst_first_and_deep_link(db_session):
    org_id = await _make_org(db_session)
    # A proven silent gap (worst), a stale technique, and a draft to review.
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=3),
        verdicts=[("T1003", "silent_gap")],
    )
    await _seed_run(
        db_session,
        org_id,
        generated_at=_NOW - timedelta(days=300),
        verdicts=[("T1055", "validated")],
    )
    await _seed_proposal(db_session, org_id, techniques=["T1566"], state="proposed")

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    kinds = [a.kind for a in console.next_best_actions]
    assert kinds, "a console with known holes must propose something to do"
    # Worst-first: the proven coverage hole leads.
    assert console.next_best_actions[0].id == "nba_silent_gap"
    assert [a.priority for a in console.next_best_actions] == sorted(
        a.priority for a in console.next_best_actions
    )
    # Every action hands off to a real surface, not a dead end.
    assert all(
        a.link in {"/detection-proposals", "/detection-validation", "/hunt-packs"}
        for a in console.next_best_actions
    )
    by_id = {a.id: a for a in console.next_best_actions}
    assert "T1003" in by_id["nba_silent_gap"].technique_ids
    assert by_id["nba_drafts"].count == 1


async def test_empty_org_returns_an_honest_empty_console(db_session):
    org_id = await _make_org(db_session)

    console = await build_coverage_console(db_session, org_id=org_id, now=_NOW)

    assert console.techniques == []
    assert console.tactics == []
    assert console.broken_rules == []
    assert console.telemetry_gaps == []
    assert console.next_best_actions == []
    assert console.verdict_counts.total == 0
    assert console.summary.total_techniques == 0
    assert console.summary.open_proposals == 0
    # Nothing to do is reported as nothing to do — not as a fabricated action.
    assert console.generated_at == _NOW


async def test_console_is_strictly_org_scoped(db_session):
    org_a = await _make_org(db_session)
    org_b = await _make_org(db_session)

    # Org A gets a full picture: coverage, a broken rule, a proposal.
    await _seed_run(
        db_session,
        org_a,
        generated_at=_NOW - timedelta(days=2),
        verdicts=[("T1059", "validated"), ("T1003", "silent_gap")],
    )
    await _seed_proposal(db_session, org_a, techniques=["T1078"], state="proposed")
    pack_a = generate_id("pack")
    rule_a = generate_id("rule")
    for day in range(4):
        await _seed_pack_run(
            db_session,
            org_a,
            pack_id=pack_a,
            started_at=_NOW - timedelta(days=day),
            rule_stats={rule_a: {"title": "A chronic", "hits": 9, "errors": 0}},
        )

    console_a = await build_coverage_console(db_session, org_id=org_a, now=_NOW)
    console_b = await build_coverage_console(db_session, org_id=org_b, now=_NOW)

    assert {c.technique_id for c in console_a.techniques} == {"T1059", "T1003", "T1078"}
    assert console_a.summary.broken_rules == 1
    assert console_a.verdict_counts.total == 2

    # Org B seeded nothing: it sees nothing of org A's, on every axis.
    assert console_b.techniques == []
    assert console_b.broken_rules == []
    assert console_b.telemetry_gaps == []
    assert console_b.next_best_actions == []
    assert console_b.verdict_counts.total == 0
    assert console_b.summary.total_techniques == 0
    assert console_b.summary.open_proposals == 0
    assert console_b.summary.broken_rules == 0
