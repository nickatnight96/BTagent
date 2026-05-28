"""Tests for the PDF report export endpoint and renderer (#145).

Covers three layers:

* The pure renderer (``services.report_pdf.render_report_pdf``) — asserts the
  output is a real PDF, embeds the TLP marking, and refuses TLP:RED via the
  shared ``assert_tlp_allows_egress`` gate (same gate the STIX export uses).
* The ``GET /api/v1/reports/{id}/export`` endpoint — content-type, ``%PDF``
  magic, scoping, and the TLP:RED 403 (mirroring ``GET /iocs/export``).

The endpoint success path mocks ``export_report_pdf`` because the underlying
report plugin is backed by a mock investigation store that only knows
``inv_mock_001``; the existing report endpoints share that limitation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from btagent_shared.security import TLPViolation
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow
from btagent_backend.services.report_pdf import render_report_pdf

# A minimal report dict shaped like the report generator's output.
_SAMPLE_REPORT = {
    "investigation_id": "inv_mock_001",
    "template": "incident_report",
    "template_title": "Incident Report",
    "generated_at": "2026-05-28 12:00 UTC",
    "sections": {
        "executive_summary": "A high-severity incident was identified.",
        "iocs": "## Indicators of Compromise\n- 198.51.100.23\n- malicious-domain.com",
    },
    "section_count": 2,
    "status": "success",
}


# --------------------------------------------------------------------------- #
# Renderer
# --------------------------------------------------------------------------- #


def test_render_pdf_returns_pdf_bytes():
    """A green report renders to real PDF bytes (``%PDF`` magic)."""
    pdf = render_report_pdf(_SAMPLE_REPORT, tlp_level="green", severity="high")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 500  # non-trivial document


def test_render_pdf_embeds_tlp_marking():
    """The TLP marking string is embedded in the rendered PDF stream."""
    pdf = render_report_pdf(_SAMPLE_REPORT, tlp_level="amber", severity="medium")
    # reportlab writes drawn strings verbatim into the content stream.
    assert b"TLP:AMBER" in pdf


def test_render_pdf_amber_strict_marking_normalised():
    """``amber_strict`` renders as the canonical ``TLP:AMBER:STRICT`` marking."""
    pdf = render_report_pdf(_SAMPLE_REPORT, tlp_level="amber_strict", severity="low")
    assert b"TLP:AMBER:STRICT" in pdf


def test_render_pdf_red_context_raises():
    """A TLP:RED context is refused by the shared egress gate, not rendered."""
    with pytest.raises(TLPViolation):
        render_report_pdf(_SAMPLE_REPORT, tlp_level="red", severity="critical")


def test_render_pdf_red_tagged_section_blocks():
    """A TLP:RED tag embedded in the report payload trips the recursive scan."""
    tagged = {**_SAMPLE_REPORT, "tlp_level": "red"}
    with pytest.raises(TLPViolation):
        render_report_pdf(tagged, tlp_level="green", severity="high")


# --------------------------------------------------------------------------- #
# Endpoint
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_export_endpoint_returns_pdf(
    client: AsyncClient,
    analyst_token: str,
    sample_investigation: InvestigationRow,
):
    """The export endpoint returns a PDF with the right content-type + magic."""
    real_pdf = render_report_pdf(_SAMPLE_REPORT, tlp_level="green", severity="high")

    with patch(
        "btagent_backend.services.report_service.ReportService.export_report_pdf",
        return_value=real_pdf,
    ):
        resp = await client.get(
            f"/api/v1/reports/{sample_investigation.id}/export?format=pdf",
            headers=auth_header(analyst_token),
        )

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
    assert "attachment" in resp.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_export_endpoint_blocks_tlp_red(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """A TLP:RED investigation is refused with 403 (mirrors STIX export)."""
    red_inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="Restricted Case",
        description="restricted",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="red",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(red_inv)
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/reports/{red_inv.id}/export?format=pdf",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403
    assert "TLP:RED" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_export_endpoint_404_for_unknown_investigation(
    client: AsyncClient,
    analyst_token: str,
):
    """An unknown investigation 404s before any rendering happens."""
    resp = await client.get(
        "/api/v1/reports/inv_does_not_exist/export?format=pdf",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_endpoint_requires_auth(
    client: AsyncClient,
    sample_investigation: InvestigationRow,
):
    """Unauthenticated export is rejected."""
    resp = await client.get(
        f"/api/v1/reports/{sample_investigation.id}/export?format=pdf",
    )
    assert resp.status_code in (401, 403)
