"""Tests for the TAXII 2.1 poll + ingest sweep (#105 / UC-2.1).

What this pins down:

* a mock poll ingests the fixture objects **through the existing stix_service
  path** and advances the feed cursor;
* TLP is derived from each object's STIX markings, exactly as the bundle
  import does (no second, drifting ingest);
* a second poll is incremental (nothing re-ingested, cursor untouched);
* one failing feed does not abort the sweep — the others still poll, and the
  failure is recorded on the failing row;
* org-scoping: a tenant's polled IOCs land in that tenant's org, and the sweep
  covers every tenant rather than only the default org;
* the resolved credential is never persisted (only the ``${secret:...}``
  reference is) and never reaches a log record or a stored error string.

Shared-DB isolation: every count assertion is scoped to a dedicated per-test
organization (``generate_id("org")``), never ``DEFAULT_ORG_ID``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
from btagent_engine.integrations.taxii import (
    MOCK_DEFAULT_COLLECTION_ID,
    MOCK_PHISHING_COLLECTION_ID,
    TaxiiHTTPError,
)
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import IOCRow, OrganizationRow
from btagent_backend.db.models_cti import TaxiiFeedRow
from btagent_backend.services import taxii_feed_service, taxii_poll_service

SERVER = "https://taxii.example.test/api1"
_REAL_TOKEN = "super-secret-taxii-token-value"
_TOKEN_ENV = "BTAGENT_TEST_TAXII_TOKEN"
_TOKEN_REF = f"${{env:{_TOKEN_ENV}}}"


@pytest.fixture(autouse=True)
def _mock_connectors(monkeypatch):
    """Mock-first: fixture collections, zero network egress."""
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    yield


def _make_org(db_session: AsyncSession) -> OrganizationRow:
    org = OrganizationRow(
        id=generate_id("org"),
        name=f"Org {generate_id('n')}",
        created_at=datetime.now(UTC),
    )
    db_session.add(org)
    return org


async def _make_feed(
    db_session: AsyncSession,
    *,
    org_id: str,
    collection_id: str = MOCK_DEFAULT_COLLECTION_ID,
    name: str | None = None,
    auth_style: str = "none",
    auth_secret_ref: str = "",
) -> TaxiiFeedRow:
    return await taxii_feed_service.create_feed(
        db_session,
        org_id=org_id,
        name=name or f"Feed {generate_id('f')}",
        server_url=SERVER,
        collection_id=collection_id,
        auth_style=auth_style,
        auth_secret_ref=auth_secret_ref,
    )


async def _org_iocs(db_session: AsyncSession, org_id: str) -> list[IOCRow]:
    rows = (await db_session.execute(select(IOCRow).where(IOCRow.org_id == org_id))).scalars().all()
    return list(rows)


# --------------------------------------------------------------------------- #
# Due-ness
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_never_polled_feed_is_due(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    assert taxii_poll_service.is_due(feed) is True


@pytest.mark.asyncio
async def test_recently_polled_feed_is_not_due(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    now = datetime.now(UTC)
    feed.last_polled_at = now - timedelta(minutes=5)
    feed.poll_interval_minutes = 60
    assert taxii_poll_service.is_due(feed, now=now) is False
    feed.last_polled_at = now - timedelta(minutes=61)
    assert taxii_poll_service.is_due(feed, now=now) is True


@pytest.mark.asyncio
async def test_disabled_feed_is_never_due(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    feed.enabled = False
    assert taxii_poll_service.is_due(feed) is False


# --------------------------------------------------------------------------- #
# Poll + ingest
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_mock_poll_ingests_objects_and_advances_cursor(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    await db_session.commit()

    outcome = await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()

    assert outcome.status == "ok"
    assert outcome.objects_fetched == 3
    assert outcome.iocs_created == 3
    assert outcome.cursor_advanced is True

    assert feed.last_cursor == "2026-07-22T08:00:00.000000Z"
    assert feed.last_status == "ok"
    assert feed.last_polled_at is not None
    assert feed.objects_ingested == 3
    assert feed.intake_investigation_id is not None

    iocs = await _org_iocs(db_session, org.id)
    assert {i.type for i in iocs} == {"ip", "domain", "hash_sha256"}
    assert all(i.source.startswith("taxii:") for i in iocs)
    assert all(i.investigation_id == feed.intake_investigation_id for i in iocs)


@pytest.mark.asyncio
async def test_ingest_derives_tlp_from_stix_markings(db_session: AsyncSession):
    """TLP handled exactly as the bundle import handles it — same code path."""
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    await db_session.commit()

    await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()

    by_value = {i.value: i for i in await _org_iocs(db_session, org.id)}
    # Fixture indicator carries the TLP:AMBER marking definition.
    assert by_value["185.220.101.42"].tlp_level == "amber"
    # …and this one TLP:GREEN.
    assert by_value["c2-server.xyz"].tlp_level == "green"


@pytest.mark.asyncio
async def test_second_poll_is_incremental(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    await db_session.commit()

    await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()
    cursor_after_first = feed.last_cursor

    second = await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()

    assert second.objects_fetched == 0
    assert second.iocs_created == 0
    assert second.cursor_advanced is False
    # An empty poll must NOT move the cursor (that would skip objects).
    assert feed.last_cursor == cursor_after_first
    assert len(await _org_iocs(db_session, org.id)) == 3


@pytest.mark.asyncio
async def test_poll_reuses_the_same_intake_case(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()
    feed = await _make_feed(db_session, org_id=org.id)
    await db_session.commit()

    await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()
    first_case = feed.intake_investigation_id

    feed.last_cursor = None  # force a re-poll of the same objects
    await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()

    assert feed.intake_investigation_id == first_case


# --------------------------------------------------------------------------- #
# Sweep — best-effort isolation + multi-tenancy
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_sweep_polls_every_tenant_and_scopes_iocs(db_session: AsyncSession):
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.commit()

    await _make_feed(db_session, org_id=org_a.id, collection_id=MOCK_DEFAULT_COLLECTION_ID)
    await _make_feed(db_session, org_id=org_b.id, collection_id=MOCK_PHISHING_COLLECTION_ID)
    await db_session.commit()

    result = await taxii_poll_service.poll_due_feeds(db_session)
    await db_session.commit()

    # Other tests may leave feeds behind in the shared DB, so assert on this
    # run's orgs rather than on the global totals.
    per_org = {o.org_id: o for o in result.outcomes if o.org_id in (org_a.id, org_b.id)}
    assert per_org[org_a.id].status == "ok"
    assert per_org[org_b.id].status == "ok"

    assert len(await _org_iocs(db_session, org_a.id)) == 3
    assert len(await _org_iocs(db_session, org_b.id)) == 2
    # No cross-tenant leakage of the other collection's indicators.
    assert "payroll@example-invoices.test" not in {
        i.value for i in await _org_iocs(db_session, org_a.id)
    }


@pytest.mark.asyncio
async def test_one_failing_feed_does_not_abort_the_others(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    bad = await _make_feed(db_session, org_id=org.id, name="Broken feed")
    good = await _make_feed(db_session, org_id=org.id, name="Working feed")
    # Point the bad feed at a collection the mock server does not serve.
    bad.collection_id = "collection--does-not-exist"
    await db_session.commit()

    result = await taxii_poll_service.poll_due_feeds(db_session)
    await db_session.commit()

    outcomes = {o.feed_id: o for o in result.outcomes}
    assert outcomes[bad.id].status == "error"
    assert outcomes[good.id].status == "ok"
    assert outcomes[good.id].iocs_created == 3

    assert bad.last_status == "error"
    assert bad.last_error
    assert bad.last_cursor is None
    assert good.last_status == "ok"
    # The good feed's objects still landed despite the sibling failure.
    assert len(await _org_iocs(db_session, org.id)) == 3


@pytest.mark.asyncio
async def test_sweep_skips_disabled_and_not_due_feeds(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    disabled = await _make_feed(db_session, org_id=org.id, name="Disabled")
    disabled.enabled = False
    not_due = await _make_feed(db_session, org_id=org.id, name="Not due")
    not_due.last_polled_at = datetime.now(UTC)
    not_due.poll_interval_minutes = 720
    await db_session.commit()

    result = await taxii_poll_service.poll_due_feeds(db_session)
    await db_session.commit()

    ids = {o.feed_id: o.status for o in result.outcomes}
    assert disabled.id not in ids  # never enumerated at all
    assert ids[not_due.id] == "skipped"
    assert await _org_iocs(db_session, org.id) == []


# --------------------------------------------------------------------------- #
# Secret hygiene
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_credential_material_is_never_persisted(db_session: AsyncSession, monkeypatch):
    """Only the reference is stored; the resolved token appears nowhere."""
    monkeypatch.setenv(_TOKEN_ENV, _REAL_TOKEN)
    org = _make_org(db_session)
    await db_session.commit()

    feed = await _make_feed(
        db_session,
        org_id=org.id,
        auth_style="bearer",
        auth_secret_ref=_TOKEN_REF,
    )
    await db_session.commit()

    await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()

    assert feed.auth_secret_ref == _TOKEN_REF
    row_dump = " ".join(str(getattr(feed, col.name)) for col in TaxiiFeedRow.__table__.columns)
    assert _REAL_TOKEN not in row_dump

    # …and it did not leak into the ingested IOC rows either.
    ioc_dump = " ".join(
        f"{i.value} {i.context} {i.source} {i.enrichment}"
        for i in await _org_iocs(db_session, org.id)
    )
    assert _REAL_TOKEN not in ioc_dump


@pytest.mark.asyncio
async def test_credential_material_is_never_logged(db_session: AsyncSession, monkeypatch, caplog):
    monkeypatch.setenv(_TOKEN_ENV, _REAL_TOKEN)
    org = _make_org(db_session)
    await db_session.commit()

    feed = await _make_feed(
        db_session,
        org_id=org.id,
        auth_style="bearer",
        auth_secret_ref=_TOKEN_REF,
    )
    await db_session.commit()

    with caplog.at_level(logging.DEBUG):
        await taxii_poll_service.poll_feed(db_session, feed)
        await db_session.commit()

    combined = " ".join(r.getMessage() for r in caplog.records)
    assert _REAL_TOKEN not in combined
    # The reference itself names a Vault/env path — also not worth logging.
    assert _TOKEN_REF not in combined


@pytest.mark.asyncio
async def test_stored_error_is_scrubbed_of_credential_material(
    db_session: AsyncSession, monkeypatch
):
    """A failing poll persists a reason — it must not persist the token."""
    monkeypatch.setenv(_TOKEN_ENV, _REAL_TOKEN)
    org = _make_org(db_session)
    await db_session.commit()

    feed = await _make_feed(
        db_session,
        org_id=org.id,
        auth_style="bearer",
        auth_secret_ref=_TOKEN_REF,
    )
    await db_session.commit()

    class _LeakyClient:
        async def poll(self, *args, **kwargs):
            raise TaxiiHTTPError(status_code=401, detail=f"rejected token {_REAL_TOKEN}")

    monkeypatch.setattr(
        taxii_poll_service,
        "TaxiiClient",
        lambda **kwargs: _LeakyClient(),
    )

    result = await taxii_poll_service.poll_due_feeds(db_session)
    await db_session.commit()

    outcome = next(o for o in result.outcomes if o.feed_id == feed.id)
    assert outcome.status == "error"
    assert _REAL_TOKEN not in outcome.error
    assert _REAL_TOKEN not in feed.last_error
    assert "[REDACTED" in feed.last_error


@pytest.mark.asyncio
async def test_unresolvable_reference_falls_back_to_mock_credential(
    db_session: AsyncSession, monkeypatch
):
    """A fixture poll must never require live secret material."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    org = _make_org(db_session)
    await db_session.commit()

    feed = await _make_feed(
        db_session,
        org_id=org.id,
        auth_style="bearer",
        auth_secret_ref=_TOKEN_REF,
    )
    await db_session.commit()

    outcome = await taxii_poll_service.poll_feed(db_session, feed)
    await db_session.commit()
    assert outcome.status == "ok"
    assert outcome.iocs_created == 3


# --------------------------------------------------------------------------- #
# Job wiring
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_job_is_registered_on_the_worker():
    from btagent_backend.scheduler.jobs import taxii_feed_poll_sweep
    from btagent_backend.scheduler.worker import WorkerSettings

    assert taxii_feed_poll_sweep in WorkerSettings.functions
    assert any(
        getattr(job, "coroutine", None) is taxii_feed_poll_sweep
        or getattr(job, "name", "") == "taxii_feed_poll_sweep"
        for job in WorkerSettings.cron_jobs
    )


@pytest.mark.asyncio
async def test_disabled_gate_short_circuits_the_job(monkeypatch):
    from btagent_backend.config import get_settings
    from btagent_backend.scheduler.jobs import taxii_feed_poll_sweep

    monkeypatch.setenv("BTAGENT_TAXII_POLL_ENABLED", "false")
    get_settings.cache_clear()
    try:
        counts = await taxii_feed_poll_sweep({})
    finally:
        get_settings.cache_clear()
    assert counts["feeds_considered"] == 0
    assert counts["iocs_created"] == 0


@pytest.mark.asyncio
async def test_enabled_feed_count_is_org_agnostic(db_session: AsyncSession):
    """The sweep's work list spans tenants (not just DEFAULT_ORG_ID)."""
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.commit()
    await _make_feed(db_session, org_id=org_a.id, name="Tenant A")
    await _make_feed(db_session, org_id=org_b.id, name="Tenant B")
    await db_session.commit()

    all_feeds = await taxii_feed_service.list_enabled_feeds_all_orgs(db_session)
    org_ids = {f.org_id for f in all_feeds}
    assert {org_a.id, org_b.id} <= org_ids

    # Sanity: the underlying table really does hold rows for both.
    count = (
        await db_session.execute(
            select(func.count(TaxiiFeedRow.id)).where(TaxiiFeedRow.org_id.in_([org_a.id, org_b.id]))
        )
    ).scalar_one()
    assert count == 2
