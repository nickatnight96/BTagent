"""`POST /reports/generate` works on a real investigation (#554).

Before this, the endpoint could not succeed for **any** case. The route scoped
``investigation_id`` against Postgres and then handed the id to a generator
that resolved investigations from a hardcoded fixture dict holding one
synthetic id:

* a real case passed scoping, missed the fixture lookup, and 400'd;
* ``inv_mock_001`` was not in the database, so it 404'd at scoping.

Nothing failed, because no test drove the endpoint with a case that existed —
the export test mocked the service out precisely because of this limitation.
These tests drive the real route against real rows, so the two halves have to
agree.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    ContainmentActionRow,
    InvestigationRow,
    IOCRow,
    TimelineEntryRow,
)


async def _seed_case(db: AsyncSession, user_id: str, *, populated: bool) -> InvestigationRow:
    """A case, optionally with the evidence a finished report needs."""
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="VPN credential stuffing",
        description="Repeated failed logins from one ASN",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=user_id,
    )
    db.add(inv)
    await db.flush()

    if populated:
        db.add(
            IOCRow(
                id=generate_id("ioc"),
                org_id=DEFAULT_ORG_ID,
                investigation_id=inv.id,
                type="ip",
                value="203.0.113.7",
                enrichment={"reputation": "malicious", "country": "NL"},
            )
        )
        db.add(
            TimelineEntryRow(
                id=generate_id("evt"),
                investigation_id=inv.id,
                timestamp=datetime(2026, 8, 1, 10, 0, tzinfo=UTC),
                description="First blocked login burst",
                technique_id="T1110.004",
            )
        )
        db.add(
            ContainmentActionRow(
                id=generate_id("act"),
                investigation_id=inv.id,
                action_type="block_ip",
                target="203.0.113.7",
            )
        )
    await db.commit()
    return inv


@pytest.mark.asyncio
async def test_generate_report_for_a_real_investigation(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """The case's own facts reach the report — the whole point of the fix."""
    inv = await _seed_case(db_session, sample_user.id, populated=True)

    resp = await client.post(
        "/api/v1/reports/generate",
        json={"investigation_id": inv.id, "template": "incident_report"},
        headers=auth_header(analyst_token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert body["investigation_id"] == inv.id

    sections = body["sections"]
    # Each assertion pins a different table flowing through: the case row, the
    # IOC rows, the timeline (and its technique), and containment actions.
    assert "VPN credential stuffing" in sections["executive_summary"]
    assert "203.0.113.7" in sections["iocs"]
    assert "First blocked login burst" in sections["timeline"]
    assert "T1110.004" in sections["findings"]
    assert "block_ip" in sections["containment"] or "203.0.113.7" in sections["containment"]


@pytest.mark.asyncio
async def test_generate_report_on_a_sparse_case_reports_gaps(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """A case with no evidence scores incomplete rather than clean.

    The failure mode worth guarding is a completeness block that measures the
    template instead of the case: it would read 100% on an empty investigation
    and an analyst would sign off on nothing.
    """
    inv = await _seed_case(db_session, sample_user.id, populated=False)

    resp = await client.post(
        "/api/v1/reports/generate",
        json={"investigation_id": inv.id, "template": "cisa_incident"},
        headers=auth_header(analyst_token),
    )

    assert resp.status_code == 200, resp.text
    completeness = resp.json()["completeness"]
    assert completeness["completeness_pct"] < 100
    assert completeness["gaps"]


@pytest.mark.asyncio
async def test_generate_report_still_404s_for_an_unknown_case(
    client: AsyncClient,
    analyst_token: str,
):
    """Scoping is unchanged: an id with no row is a 404, not a report."""
    resp = await client.post(
        "/api/v1/reports/generate",
        json={"investigation_id": "inv_does_not_exist", "template": "incident_report"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_pdf_renders_a_real_case(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """PDF export shared the same broken path, so it gets the same proof.

    Nothing is mocked here — the bytes come from generating a report on a real
    row and rendering it.
    """
    inv = await _seed_case(db_session, sample_user.id, populated=True)

    resp = await client.get(
        f"/api/v1/reports/{inv.id}/export?format=pdf",
        headers=auth_header(analyst_token),
    )

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
