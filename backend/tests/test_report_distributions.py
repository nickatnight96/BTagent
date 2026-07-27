"""Tests for report distribution tracking and the regulatory-notification clock.

EPIC-6 UC-6.2:

* Part A — the org-scoped ``report_distributions`` audit ledger: the service
  ``record_distribution`` / ``list_distributions`` round-trip, strict
  org-scoping (one tenant never sees another's rows), and the read-only
  ``GET /reports/distributions`` surface.
* Part C — the regulatory-notification clock: ``generate_report`` for the
  ``regulatory_notification`` template attaches SEC (4 business days), NIS2
  (24h), and DORA (72h) deadlines computed from the detection time.

Shared-DB isolation: the in-memory SQLite is session-scoped and committed rows
persist across the whole run, so every exact-count assertion here is scoped to
a dedicated per-test organization (``generate_id("org")``) or to a freshly
generated ``report_id`` — never to ``DEFAULT_ORG_ID`` at large.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    OrganizationRow,
    ReportDistributionRow,
)
from btagent_backend.services.report_service import ReportService


def _make_org(db_session: AsyncSession) -> OrganizationRow:
    org = OrganizationRow(
        id=generate_id("org"),
        name=f"Org {generate_id('n')}",
        created_at=datetime.now(UTC),
    )
    db_session.add(org)
    return org


# --------------------------------------------------------------------------- #
# Part A — service: persistence + org-scoping
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_record_distribution_persists_all_fields(db_session: AsyncSession):
    """``record_distribution`` writes a row that round-trips every field."""
    svc = ReportService()
    org = _make_org(db_session)
    await db_session.commit()

    report_id = generate_id("rpt")
    row = await svc.record_distribution(
        db_session,
        org_id=org.id,
        report_id=report_id,
        audience="cisa_liaison",
        recipient="liaison@cisa.gov",
        tlp_applied="amber",
        approver_id="usr_approver_1",
    )

    assert row.id.startswith("rdist_")
    assert row.org_id == org.id
    assert row.report_id == report_id
    assert row.audience == "cisa_liaison"
    assert row.recipient == "liaison@cisa.gov"
    assert row.tlp_applied == "amber"
    assert row.approver_id == "usr_approver_1"
    assert row.sent_at is not None

    # Round-trips through a fresh query.
    rows = await svc.list_distributions(db_session, org_id=org.id)
    assert [r.id for r in rows] == [row.id]


@pytest.mark.asyncio
async def test_list_distributions_is_org_scoped(db_session: AsyncSession):
    """A tenant's distribution ledger never leaks another tenant's rows."""
    svc = ReportService()
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.commit()

    await svc.record_distribution(
        db_session,
        org_id=org_a.id,
        report_id="rpt_a1",
        audience="leadership",
        recipient="#leadership",
    )
    await svc.record_distribution(
        db_session,
        org_id=org_a.id,
        report_id="rpt_a1",
        audience="cisa_liaison",
        recipient="liaison@cisa.gov",
    )
    await svc.record_distribution(
        db_session,
        org_id=org_b.id,
        report_id="rpt_b1",
        audience="leadership",
        recipient="#exec",
    )

    a_rows = await svc.list_distributions(db_session, org_id=org_a.id)
    b_rows = await svc.list_distributions(db_session, org_id=org_b.id)

    # Exact counts are safe: both orgs are dedicated to this test.
    assert len(a_rows) == 2
    assert len(b_rows) == 1
    assert all(r.org_id == org_a.id for r in a_rows)
    assert org_b.id not in {r.org_id for r in a_rows}


@pytest.mark.asyncio
async def test_list_distributions_filters_by_report_id(db_session: AsyncSession):
    """The optional ``report_id`` filter narrows to a single report."""
    svc = ReportService()
    org = _make_org(db_session)
    await db_session.commit()

    target = generate_id("rpt")
    other = generate_id("rpt")
    await svc.record_distribution(
        db_session, org_id=org.id, report_id=target, audience="leadership", recipient="#a"
    )
    await svc.record_distribution(
        db_session, org_id=org.id, report_id=other, audience="leadership", recipient="#b"
    )

    only = await svc.list_distributions(db_session, org_id=org.id, report_id=target)
    assert len(only) == 1
    assert only[0].report_id == target


# --------------------------------------------------------------------------- #
# Part A — API: read-only audit surface
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_distributions_endpoint_scopes_to_caller_org(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """``GET /reports/distributions`` returns only the caller-org's rows."""
    unique_report = generate_id("rpt")

    mine = ReportDistributionRow(
        id=generate_id("rdist"),
        org_id=DEFAULT_ORG_ID,  # sample_user lives in the default org
        report_id=unique_report,
        audience="cisa_liaison",
        recipient="liaison@cisa.gov",
        tlp_applied="amber",
        approver_id=sample_user.id,
        sent_at=datetime.now(UTC),
    )
    other_org = _make_org(db_session)
    theirs = ReportDistributionRow(
        id=generate_id("rdist"),
        org_id=other_org.id,
        report_id=unique_report,  # same report id, different tenant
        audience="leadership",
        recipient="#exec",
        tlp_applied="amber",
        sent_at=datetime.now(UTC),
    )
    db_session.add_all([mine, theirs])
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/reports/distributions?report_id={unique_report}",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    data = resp.json()
    # Exact for this freshly generated report_id within the caller's org.
    assert data["count"] == 1
    assert data["status"] == "success"
    ids = {d["id"] for d in data["distributions"]}
    assert mine.id in ids
    assert theirs.id not in ids  # cross-org row is invisible
    assert data["distributions"][0]["audience"] == "cisa_liaison"
    assert data["distributions"][0]["approver_id"] == sample_user.id


@pytest.mark.asyncio
async def test_distributions_endpoint_requires_auth(client: AsyncClient):
    """Unauthenticated access to the audit surface is rejected."""
    resp = await client.get("/api/v1/reports/distributions")
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Part C — regulatory-notification clock
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_regulatory_notification_attaches_clock():
    """The regulatory template stamps SEC/NIS2/DORA deadlines from detection."""
    svc = ReportService()
    # 2025-03-20 is a Thursday.
    detected = datetime(2025, 3, 20, 8, 30, tzinfo=UTC)

    report = await svc.generate_report(
        "inv_mock_001", "regulatory_notification", detected_at=detected
    )
    assert report["status"] == "success"

    clock = report["regulatory_deadlines"]
    assert clock["detected_at"] == detected.isoformat()
    regimes = clock["regimes"]

    # Fixed-offset windows.
    assert regimes["nis2"]["deadline"] == (detected + timedelta(hours=24)).isoformat()
    assert regimes["dora"]["deadline"] == (detected + timedelta(hours=72)).isoformat()
    # SEC = 4 business days from Thu 2025-03-20 → Wed 2025-03-26 (skips the weekend).
    assert regimes["sec"]["deadline"] == datetime(2025, 3, 26, 8, 30, tzinfo=UTC).isoformat()

    # The template section is populated (not left as a pending stub).
    section = report["sections"]["regulatory_deadline"]
    assert section.lstrip().startswith("##")
    assert "Regulatory Notification Deadlines" in section
    assert "SEC" in section and "NIS2" in section and "DORA" in section


@pytest.mark.asyncio
async def test_non_regulatory_template_has_no_clock():
    """Non-regulatory templates carry no regulatory-deadline block."""
    svc = ReportService()
    report = await svc.generate_report("inv_mock_001", "incident_report")
    assert report["status"] == "success"
    assert "regulatory_deadlines" not in report
