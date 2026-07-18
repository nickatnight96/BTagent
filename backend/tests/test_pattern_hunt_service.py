"""Tests for the Cross-Investigation Pattern Hunter service (#120).

Covers the corpus walk + persistence against the in-memory SQLite DB: weak
signals are upserted from closed investigations, top-N proposals are created
with non-empty HuntInputs, re-scans upsert (no duplicates), and dismiss/snooze
down-weights the same cluster on a subsequent scan.
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.types.pattern_hunt import ProposalState
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow, IOCRow
from btagent_backend.db.models_pattern import PatternHuntProposalRow, WeakSignalRow
from btagent_backend.services import pattern_hunt_service as svc

NOW = datetime(2026, 6, 18, tzinfo=UTC)


async def _add_investigation(
    db,
    *,
    inv_id: str,
    status: str = "closed",
    closed_offset_days: int = 1,
    config: dict | None = None,
) -> InvestigationRow:
    inv = InvestigationRow(
        id=inv_id,
        org_id=DEFAULT_ORG_ID,
        title=f"Case {inv_id}",
        description="",
        status=status,
        severity="medium",
        tlp_level="green",
        config=config or {},
        created_at=NOW - timedelta(days=closed_offset_days + 1),
        updated_at=NOW - timedelta(days=closed_offset_days),
        closed_at=NOW - timedelta(days=closed_offset_days),
    )
    db.add(inv)
    await db.flush()
    return inv


async def _add_ioc(db, *, inv_id: str, ioc_type: str, value: str, enrichment: dict | None = None):
    ioc = IOCRow(
        id=generate_id("ioc"),
        org_id=DEFAULT_ORG_ID,
        investigation_id=inv_id,
        type=ioc_type,
        value=value,
        enrichment=enrichment or {},
    )
    db.add(ioc)
    await db.flush()
    return ioc


# --------------------------------------------------------------------------- #
# Corpus walk + persistence
# --------------------------------------------------------------------------- #


async def test_scan_persists_weak_signals_and_proposals(db_session):
    # A shared C2 domain across 3 closed investigations + per-case noise.
    for i in range(3):
        await _add_investigation(db_session, inv_id=f"inv_ws_{i}", closed_offset_days=i + 1)
        await _add_ioc(
            db_session, inv_id=f"inv_ws_{i}", ioc_type="domain", value=f"n{i}.shared-c2.net"
        )
        await _add_ioc(db_session, inv_id=f"inv_ws_{i}", ioc_type="ip", value=f"203.0.{i}.9")

    result = await svc.scan_corpus(db_session, top_n=10, now=NOW)

    assert result.investigations_scanned == 3
    assert result.weak_signals_upserted > 0
    assert result.proposals_created >= 1

    # The TLD cluster (shared-c2.net across 3 cases) must produce a proposal.
    proposals = (await db_session.execute(select(PatternHuntProposalRow))).scalars().all()
    assert proposals
    tld_proposals = [p for p in proposals if "shared-c2-net" in p.cluster_id]
    assert tld_proposals, [p.cluster_id for p in proposals]
    prop = tld_proposals[0]
    assert prop.state == ProposalState.PROPOSED.value
    # HuntInput is non-empty + serialised.
    hi = prop.hunt_input
    assert hi["iocs"] or hi["ttps"] or hi["adversaries"]

    # Weak-signal row carries the pinned diversity count.
    ws_rows = (
        (await db_session.execute(select(WeakSignalRow).where(WeakSignalRow.kind == "tld")))
        .scalars()
        .all()
    )
    tld_row = next(r for r in ws_rows if r.value == "shared-c2.net")
    assert tld_row.distinct_investigation_count == 3


async def test_scan_ignores_open_investigations(db_session):
    await _add_investigation(db_session, inv_id="inv_open_1", status="investigating")
    await _add_ioc(db_session, inv_id="inv_open_1", ioc_type="domain", value="x.open-c2.net")
    await _add_investigation(db_session, inv_id="inv_open_2", status="investigating")
    await _add_ioc(db_session, inv_id="inv_open_2", ioc_type="domain", value="y.open-c2.net")

    result = await svc.scan_corpus(db_session, now=NOW)
    assert result.investigations_scanned == 0
    assert result.proposals_created == 0


async def test_rescan_upserts_without_duplicates(db_session):
    for i in range(3):
        await _add_investigation(db_session, inv_id=f"inv_re_{i}", closed_offset_days=i + 1)
        await _add_ioc(
            db_session, inv_id=f"inv_re_{i}", ioc_type="domain", value=f"n{i}.repeat-c2.net"
        )

    await svc.scan_corpus(db_session, now=NOW)
    count_1 = (await db_session.execute(select(func.count(PatternHuntProposalRow.id)))).scalar()
    # Re-run: same corpus, must not create a second proposal per cluster.
    await svc.scan_corpus(db_session, now=NOW)
    count_2 = (await db_session.execute(select(func.count(PatternHuntProposalRow.id)))).scalar()
    assert count_1 == count_2

    # Weak signals also upsert in place (no duplicate (org,kind,value) rows).
    ws_dupes = (
        await db_session.execute(
            select(WeakSignalRow.kind, WeakSignalRow.value, func.count(WeakSignalRow.id))
            .group_by(WeakSignalRow.kind, WeakSignalRow.value)
            .having(func.count(WeakSignalRow.id) > 1)
        )
    ).all()
    assert ws_dupes == []


# --------------------------------------------------------------------------- #
# Dismiss / snooze down-weighting
# --------------------------------------------------------------------------- #


async def test_dismiss_suppresses_cluster_on_next_scan(db_session):
    for i in range(3):
        await _add_investigation(db_session, inv_id=f"inv_dis_{i}", closed_offset_days=i + 1)
        await _add_ioc(
            db_session, inv_id=f"inv_dis_{i}", ioc_type="domain", value=f"n{i}.dismiss-c2.net"
        )

    await svc.scan_corpus(db_session, now=NOW)
    prop = (
        (
            await db_session.execute(
                select(PatternHuntProposalRow).where(
                    PatternHuntProposalRow.cluster_id.like("%dismiss-c2-net%")
                )
            )
        )
        .scalars()
        .one()
    )
    await svc.dismiss_proposal(db_session, proposal_id=prop.id)
    assert prop.state == ProposalState.DISMISSED.value

    # Re-scan: the dismissed cluster must be filtered out (down-weighted) and
    # NOT re-created as a fresh proposed row.
    result = await svc.scan_corpus(db_session, now=NOW)
    assert result.proposals_suppressed >= 1
    refreshed = await db_session.get(PatternHuntProposalRow, prop.id)
    assert refreshed.state == ProposalState.DISMISSED.value


async def test_snooze_suppresses_cluster_on_next_scan(db_session):
    for i in range(3):
        await _add_investigation(db_session, inv_id=f"inv_sn_{i}", closed_offset_days=i + 1)
        await _add_ioc(
            db_session, inv_id=f"inv_sn_{i}", ioc_type="domain", value=f"n{i}.snooze-c2.net"
        )

    await svc.scan_corpus(db_session, now=NOW)
    prop = (
        (
            await db_session.execute(
                select(PatternHuntProposalRow).where(
                    PatternHuntProposalRow.cluster_id.like("%snooze-c2-net%")
                )
            )
        )
        .scalars()
        .one()
    )
    await svc.snooze_proposal(db_session, proposal_id=prop.id)

    result = await svc.scan_corpus(db_session, now=NOW)
    assert result.proposals_suppressed >= 1


async def test_set_state_raises_on_unknown_proposal(db_session):
    import pytest

    with pytest.raises(ValueError, match="not found"):
        await svc.dismiss_proposal(db_session, proposal_id="phpr_missing")


# --------------------------------------------------------------------------- #
# Analyst triage rationale — dedicated column, generated rationale stays clean
# --------------------------------------------------------------------------- #


async def _seed_one_proposal(db_session) -> PatternHuntProposalRow:
    for i in range(3):
        await _add_investigation(db_session, inv_id=f"inv_tr_{i}", closed_offset_days=i + 1)
        await _add_ioc(
            db_session, inv_id=f"inv_tr_{i}", ioc_type="domain", value=f"n{i}.triage-c2.net"
        )
    await svc.scan_corpus(db_session, now=NOW)
    return (
        (
            await db_session.execute(
                select(PatternHuntProposalRow).where(
                    PatternHuntProposalRow.cluster_id.like("%triage-c2-net%")
                )
            )
        )
        .scalars()
        .one()
    )


async def test_triage_rationale_written_to_dedicated_column(db_session):
    prop = await _seed_one_proposal(db_session)
    generated = prop.rationale  # the "why this surfaced" text

    await svc.dismiss_proposal(
        db_session, proposal_id=prop.id, triage_rationale="Known-good beaconing to CDN."
    )

    refreshed = await db_session.get(PatternHuntProposalRow, prop.id)
    # The analyst note lands in the dedicated column with a state marker...
    assert "Known-good beaconing to CDN." in refreshed.triage_rationale
    assert "dismissed" in refreshed.triage_rationale
    # ...and the generated rationale is left pristine.
    assert refreshed.rationale == generated
    assert "Known-good" not in refreshed.rationale


async def test_triage_rationale_accumulates_across_transitions(db_session):
    prop = await _seed_one_proposal(db_session)

    await svc.snooze_proposal(
        db_session, proposal_id=prop.id, triage_rationale="Snooze for a week."
    )
    await svc.dismiss_proposal(
        db_session, proposal_id=prop.id, triage_rationale="Confirmed benign."
    )

    refreshed = await db_session.get(PatternHuntProposalRow, prop.id)
    assert "Snooze for a week." in refreshed.triage_rationale
    assert "Confirmed benign." in refreshed.triage_rationale
    # Both transition markers present.
    assert "snoozed" in refreshed.triage_rationale
    assert "dismissed" in refreshed.triage_rationale


async def test_empty_triage_rationale_leaves_column_null(db_session):
    prop = await _seed_one_proposal(db_session)
    await svc.dismiss_proposal(db_session, proposal_id=prop.id)  # no rationale
    refreshed = await db_session.get(PatternHuntProposalRow, prop.id)
    assert refreshed.triage_rationale is None


# --------------------------------------------------------------------------- #
# cmdline + asn extraction from enrichment
# --------------------------------------------------------------------------- #


async def test_scan_extracts_asn_and_cmdline_from_enrichment(db_session):
    for i in range(2):
        await _add_investigation(db_session, inv_id=f"inv_enr_{i}", closed_offset_days=i + 1)
        await _add_ioc(
            db_session,
            inv_id=f"inv_enr_{i}",
            ioc_type="ip",
            value=f"198.51.100.{i}",
            enrichment={"asn": "AS64511", "cmdline": "rundll32 evil.dll,Start"},
        )

    await svc.scan_corpus(db_session, now=NOW)

    asn_rows = (
        (await db_session.execute(select(WeakSignalRow).where(WeakSignalRow.kind == "asn")))
        .scalars()
        .all()
    )
    assert any(r.value == "64511" and r.distinct_investigation_count == 2 for r in asn_rows)

    cmd_rows = (
        (
            await db_session.execute(
                select(WeakSignalRow).where(WeakSignalRow.kind == "cmdline_fragment")
            )
        )
        .scalars()
        .all()
    )
    assert any("rundll32" in r.value and r.distinct_investigation_count == 2 for r in cmd_rows)


# --------------------------------------------------------------------------- #
# Scheduler wiring (the weekly_pattern_scan job + its gate)
# --------------------------------------------------------------------------- #


def test_worker_registers_weekly_pattern_scan():
    from btagent_backend.scheduler import jobs
    from btagent_backend.scheduler.worker import WorkerSettings

    assert jobs.weekly_pattern_scan in WorkerSettings.functions
    # One cron per registered recurring job; the pattern scan adds a third.
    assert len(WorkerSettings.cron_jobs) >= 3


async def test_weekly_pattern_scan_skips_and_warns_when_disabled(monkeypatch, caplog):
    import logging

    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    monkeypatch.setenv("BTAGENT_PATTERN_SCAN_ENABLED", "false")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="btagent.scheduler.jobs"):
            result = await jobs.weekly_pattern_scan({})
        assert result["investigations_scanned"] == 0
        assert result["proposals_created"] == 0
        warnings = [r for r in caplog.records if "pattern scan disabled" in r.message]
        assert len(warnings) == 1
    finally:
        get_settings.cache_clear()


def test_pattern_scan_enabled_defaults_on():
    from btagent_backend.config import Settings

    # Unlike the connector-blocked hunt-pack scheduler, the pattern scan runs
    # over already-stored data, so its gate defaults ON regardless of mocks.
    assert Settings(env="test", mock_connectors=False).pattern_scan_enabled is True


# --------------------------------------------------------------------------- #
# Finding 1 (Codex #208 P1): the weekly job scans EVERY org, not just default
# --------------------------------------------------------------------------- #


async def _seed_org_with_pattern(db, *, org_id: str, tag: str) -> None:
    """Seed an org row + 3 closed investigations sharing one C2 domain."""
    from btagent_backend.db.models import OrganizationRow

    db.add(OrganizationRow(id=org_id, name=f"Org {tag}", created_at=NOW))
    await db.flush()
    for i in range(3):
        inv_id = f"inv_{tag}_{i}"
        inv = InvestigationRow(
            id=inv_id,
            org_id=org_id,
            title=f"Case {inv_id}",
            description="",
            status="closed",
            severity="medium",
            tlp_level="green",
            config={},
            created_at=NOW - timedelta(days=i + 2),
            updated_at=NOW - timedelta(days=i + 1),
            closed_at=NOW - timedelta(days=i + 1),
        )
        db.add(inv)
        await db.flush()
        ioc = IOCRow(
            id=generate_id("ioc"),
            org_id=org_id,
            investigation_id=inv_id,
            type="domain",
            value=f"n{i}.{tag}-c2.net",
            enrichment={},
        )
        db.add(ioc)
        await db.flush()


async def test_scan_all_orgs_covers_every_org(db_session):
    """Two orgs each holding a cross-case pattern must BOTH be scanned —
    the weekly job delegates to ``scan_all_orgs``, which enumerates every org
    rather than the single DEFAULT_ORG_ID (which would exclude the second)."""
    org_a = "org_pscan_a"
    org_b = "org_pscan_b"
    await _seed_org_with_pattern(db_session, org_id=org_a, tag="alpha")
    await _seed_org_with_pattern(db_session, org_id=org_b, tag="bravo")

    result = await svc.scan_all_orgs(db_session, top_n=10, now=NOW)

    # Both seeded orgs (plus the default + any other seeded org) were scanned.
    assert result.orgs_scanned >= 2
    # 3 closed investigations per seeded org were walked.
    assert result.investigations_scanned >= 6
    assert result.proposals_created >= 2

    # Each org has its own proposal for its own TLD cluster — proof both
    # tenants (not just the default) were scanned.
    for tag in ("alpha", "bravo"):
        org_id = org_a if tag == "alpha" else org_b
        rows = (
            (
                await db_session.execute(
                    select(PatternHuntProposalRow).where(
                        PatternHuntProposalRow.org_id == org_id,
                        PatternHuntProposalRow.cluster_id.like(f"%{tag}-c2-net%"),
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows, f"no proposal scanned for org {org_id} ({tag})"


async def test_scan_all_orgs_lists_every_org(db_session):
    """``list_org_ids`` returns every org so the scan can't silently skip one."""
    await _seed_org_with_pattern(db_session, org_id="org_list_x", tag="xray")
    org_ids = await svc.list_org_ids(db_session)
    assert "org_list_x" in org_ids
    assert DEFAULT_ORG_ID in org_ids


def test_weekly_pattern_scan_delegates_to_scan_all_orgs():
    """Wiring check: the thin job shell calls the multi-org service entry."""
    import inspect

    from btagent_backend.scheduler import jobs

    src = inspect.getsource(jobs.weekly_pattern_scan)
    assert "scan_all_orgs" in src
