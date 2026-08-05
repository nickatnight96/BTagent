"""A pack-run may only be resumed while resuming still means something.

``_find_resumable_run`` exists so a worker that dies mid-sweep picks up at the
next rule instead of re-ingesting what it already committed. That is a good
design and it is deliberately checkpointed (#112).

It had no age bound, and that turned the mechanism against itself. A run
orphaned by a permanently-dead worker stays ``running`` forever, so the *next
scheduled sweep* adopts its progress cursor. That sweep executes every rule
against the SIEM as normal — and then skips *persisting* the ones the dead run
had completed, throwing its fresh hits away — before stamping the dead row
terminal under the dead run's ``run_id`` and ``started_at``.

The symptom is a sweep's worth of coverage silently missing, filed against the
wrong run, once per worker death. Nothing errors. Nothing in the history says
findings were dropped; the run reads as a normal completion at a timestamp
hours before the sweep that actually did the work.

Bounding the window fixes it because resumption was only ever meant to span a
*restart*, not a scheduled tick. Outside the window the row is abandoned — a
terminal status, so it stops claiming to be running and stops being a
candidate — and the caller opens a fresh row that ingests everything.

The window/interval relationship is the fragile part and is pinned below: a
window at or above the scheduler interval re-opens exactly the hole this
closes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import get_settings
from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow
from btagent_backend.db.models_hunt import HuntPackRunRow
from btagent_backend.services import hunt_pack_run_service as prs

_PACK_ID = "pack_stale_resume"


def _running_row(*, started_at: datetime, completed: list[str]) -> HuntPackRunRow:
    return HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=DEFAULT_ORG_ID,
        run_id=generate_id("hrun"),
        pack_id=_PACK_ID,
        pack_name="Stale Resume Pack",
        pack_version="1.0.0",
        backends=["splunk"],
        rule_stats={},
        hit_count=0,
        error_count=0,
        findings_created=0,
        status="running",
        progress={"completed_rule_ids": completed},
        started_at=started_at,
        completed_at=None,
    )


@pytest_asyncio.fixture()
async def clean_runs(db_session: AsyncSession):
    rows = (
        (await db_session.execute(select(HuntPackRunRow).where(HuntPackRunRow.pack_id == _PACK_ID)))
        .scalars()
        .all()
    )
    for row in rows:
        await db_session.delete(row)
    await db_session.commit()
    return db_session


# ---------------------------------------------------------------------------
# The window itself.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_recent_run_is_still_resumed(clean_runs: AsyncSession):
    """The behaviour the mechanism exists for — a pod restart mid-sweep."""
    row = _running_row(started_at=datetime.now(UTC) - timedelta(minutes=2), completed=["r1"])
    clean_runs.add(row)
    await clean_runs.flush()

    found = await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID)

    assert found is not None, "a run from two minutes ago must still be resumable"
    assert found.id == row.id
    assert found.status == "running"


@pytest.mark.asyncio
async def test_a_stale_run_is_not_resumed(clean_runs: AsyncSession):
    """The bug: an orphan silently suppressing the next sweep's ingest."""
    window = get_settings().hunt_run_resume_window_minutes
    row = _running_row(
        started_at=datetime.now(UTC) - timedelta(minutes=window + 30),
        completed=["r1", "r2", "r3"],
    )
    clean_runs.add(row)
    await clean_runs.flush()

    found = await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID)

    assert found is None, (
        "a stale run was adopted; the next sweep would skip persisting r1-r3 and "
        "discard the hits it just executed for them"
    )


@pytest.mark.asyncio
async def test_a_stale_run_is_marked_terminal_not_left_running(clean_runs: AsyncSession):
    """Otherwise it stays a candidate forever and history lies about it."""
    window = get_settings().hunt_run_resume_window_minutes
    row = _running_row(
        started_at=datetime.now(UTC) - timedelta(minutes=window + 30), completed=["r1"]
    )
    clean_runs.add(row)
    await clean_runs.flush()

    await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID)

    await clean_runs.refresh(row)
    assert row.status != "running", "a run nobody can resume must not stay 'running'"
    assert row.completed_at is not None
    assert "abandoned" in (row.error or "").lower()


@pytest.mark.asyncio
async def test_abandoning_is_distinguishable_from_failing(clean_runs: AsyncSession):
    """An orphan did not error, and an analyst reading history needs to know.

    Collapsing it into ``failed`` would tell someone the sweep ran and broke,
    when in fact it was interrupted and never finished.
    """
    window = get_settings().hunt_run_resume_window_minutes
    row = _running_row(started_at=datetime.now(UTC) - timedelta(minutes=window + 30), completed=[])
    clean_runs.add(row)
    await clean_runs.flush()

    await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID)

    await clean_runs.refresh(row)
    assert row.status == "abandoned"
    assert row.status != "failed"


@pytest.mark.asyncio
async def test_an_abandoned_run_is_marked_truncated(clean_runs: AsyncSession):
    """It is not a clean sweep — some rules never ran.

    Reusing the E7 truncation flag is what makes run history read correctly
    without every consumer learning a new status.
    """
    window = get_settings().hunt_run_resume_window_minutes
    row = _running_row(
        started_at=datetime.now(UTC) - timedelta(minutes=window + 30), completed=["r1"]
    )
    clean_runs.add(row)
    await clean_runs.flush()

    await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID)

    await clean_runs.refresh(row)
    assert row.truncated is True


def test_the_noise_baseline_ignores_abandoned_runs():
    """A partial sweep must not set the noise floor.

    Counting it as clean understates noise for precisely the rules that
    produced nothing *because they never executed*.
    """
    from btagent_backend.services import noise_baseline

    assert "abandoned" in noise_baseline._INCOMPLETE
    assert "failed" in noise_baseline._INCOMPLETE


@pytest.mark.asyncio
async def test_the_next_sweep_starts_clean_after_an_abandonment(clean_runs: AsyncSession):
    """End of the story: no cursor survives to suppress the next ingest."""
    window = get_settings().hunt_run_resume_window_minutes
    stale = _running_row(
        started_at=datetime.now(UTC) - timedelta(minutes=window + 30),
        completed=["r1", "r2"],
    )
    clean_runs.add(stale)
    await clean_runs.flush()

    assert (
        await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID) is None
    )
    # And again — the abandoned row must not resurface on the following tick.
    assert (
        await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID) is None
    )


@pytest.mark.asyncio
async def test_another_orgs_stale_run_is_untouched(clean_runs: AsyncSession):
    """The lookup is org-scoped; abandoning must be too."""
    other_org = "org_stale_resume_other"
    if await clean_runs.get(OrganizationRow, other_org) is None:
        clean_runs.add(OrganizationRow(id=other_org, name=other_org, created_at=datetime.now(UTC)))
        await clean_runs.flush()

    row = _running_row(started_at=datetime.now(UTC) - timedelta(minutes=999), completed=["r1"])
    row.org_id = other_org
    clean_runs.add(row)
    await clean_runs.flush()

    await prs._find_resumable_run(clean_runs, org_id=DEFAULT_ORG_ID, pack_id=_PACK_ID)

    await clean_runs.refresh(row)
    assert row.status == "running", "abandoned a run belonging to a different org"


# ---------------------------------------------------------------------------
# The window must stay smaller than the gap between sweeps.
# ---------------------------------------------------------------------------


def test_resume_window_cannot_span_a_scheduled_sweep():
    """A window >= the interval re-opens the hole this closes.

    At that point the previous tick's orphan is still "recent" when the next
    tick runs, and the next sweep adopts it — exactly the behaviour the bound
    exists to prevent.
    """
    settings = get_settings()
    window_minutes = settings.hunt_run_resume_window_minutes
    interval_minutes = settings.hunt_scheduler_interval_hours * 60
    assert window_minutes < interval_minutes, (
        f"resume window ({window_minutes}m) is not shorter than the scheduler "
        f"interval ({interval_minutes}m); an orphan would still be adopted by "
        "the next scheduled sweep"
    )


def test_resume_window_is_long_enough_for_a_pod_restart():
    """Too short and a legitimate restart re-ingests instead of resuming."""
    assert get_settings().hunt_run_resume_window_minutes >= 5
