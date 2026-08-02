"""B8/B9 / P4.2: scheduled hunt crons are multi-tenant with per-org isolation.

B8: the hunt-pack / email / deception / NDR / behavioral crons were hard-coded
to ``DEFAULT_ORG_ID`` while the pack store resolves per-org — a non-default
tenant's uploaded packs and toggles never executed, and the UI reported a
detection posture the runner didn't implement.

B9: the noise-digest and shift-handover sweeps had no per-org error isolation
and a single post-loop commit — one malformed org rolled back every previously
processed org's work and re-notified from stale state next tick.

Both fixes ride ``_run_per_org``: iterate every org, commit after each, log +
rollback + continue on failure.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from btagent_backend.config import get_settings
from btagent_backend.scheduler import jobs


class _StubSession:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def _fake_all_orgs(org_ids: list[str]):
    async def _all(session):
        return list(org_ids)

    return _all


@pytest.mark.asyncio
async def test_run_per_org_isolates_failures_and_commits_per_org():
    session = _StubSession()
    processed: list[str] = []

    async def _work(org_id: str) -> None:
        if org_id == "org_bad":
            raise RuntimeError("malformed pack run")
        processed.append(org_id)

    failures = await jobs._run_per_org(session, "test_sweep", ["org_a", "org_bad", "org_c"], _work)

    # org_a committed BEFORE org_bad ran; org_bad rolled back alone; org_c
    # still processed and committed — nothing sank the tick.
    assert failures == 1
    assert processed == ["org_a", "org_c"]
    assert session.commits == 2
    assert session.rollbacks == 1


def _job_session(session):
    """A stand-in for ``async_session_factory`` yielding a fixed session."""

    @asynccontextmanager
    async def _cm():
        yield session

    return _cm


def _enable_hunt_schedule(monkeypatch):
    """Force the hunt-schedule gate on without depending on settings caching.

    The full suite runs under pytest-randomly, so relying on env + get_settings
    cache state is order-fragile; patch the resolved flag directly.
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "hunt_schedule_enabled", True, raising=False)
    monkeypatch.setattr(jobs, "get_settings", lambda: settings)


@pytest.mark.asyncio
async def test_hunt_pack_cron_sweeps_every_org(monkeypatch):
    """B8: the cron reaches EVERY org — no hard-coded DEFAULT_ORG_ID.

    Deterministic: ``_all_org_ids`` is stubbed to a fixed set so the test never
    touches the shared in-memory org table (which other tests mutate under
    random ordering).
    """
    seen: list[str] = []

    async def _fake_run_pack_and_ingest(session, *, org_id, **kwargs):
        seen.append(org_id)
        return []

    from btagent_backend.services import hunt_pack_run_service

    monkeypatch.setattr(hunt_pack_run_service, "run_pack_and_ingest", _fake_run_pack_and_ingest)
    monkeypatch.setattr(jobs, "_all_org_ids", _fake_all_orgs(["org_a", "org_b", "org_c"]))
    monkeypatch.setattr(jobs, "async_session_factory", _job_session(_StubSession()))
    _enable_hunt_schedule(monkeypatch)

    result = await jobs.scheduled_hunt_pack_run({})

    assert result["packs_run"] == 0
    assert seen == ["org_a", "org_b", "org_c"], f"cron missed orgs: {seen}"


@pytest.mark.asyncio
async def test_hunt_pack_cron_survives_one_orgs_failure(monkeypatch):
    """B9-shape isolation on the B8 sweep: one org's crash doesn't sink the rest."""
    seen: list[str] = []

    async def _flaky_run_pack_and_ingest(session, *, org_id, **kwargs):
        seen.append(org_id)
        if org_id == "org_a":
            raise RuntimeError("boom")
        return []

    from btagent_backend.services import hunt_pack_run_service

    monkeypatch.setattr(hunt_pack_run_service, "run_pack_and_ingest", _flaky_run_pack_and_ingest)
    monkeypatch.setattr(jobs, "_all_org_ids", _fake_all_orgs(["org_a", "org_b"]))
    monkeypatch.setattr(jobs, "async_session_factory", _job_session(_StubSession()))
    _enable_hunt_schedule(monkeypatch)

    result = await jobs.scheduled_hunt_pack_run({})

    # Both orgs attempted; the tick completed despite org_a's failure.
    assert seen == ["org_a", "org_b"]
    assert result["packs_run"] == 0
