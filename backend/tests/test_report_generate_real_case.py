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


# --------------------------------------------------------------------------- #
# #557 — the same defect in the sibling endpoints
# --------------------------------------------------------------------------- #
#
# `/reports/remediation` and `/reports/summarize` delegate to two more plugin
# tools with an identical `_MOCK_INVESTIGATIONS` lookup, so they failed for
# real cases exactly the way generation did. Same seam, same proof.


@pytest.mark.asyncio
async def test_remediation_for_a_real_investigation(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    inv = await _seed_case(db_session, sample_user.id, populated=True)

    resp = await client.post(
        "/api/v1/reports/remediation",
        json={"investigation_id": inv.id, "audience": "technical"},
        headers=auth_header(analyst_token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert body["investigation_id"] == inv.id


@pytest.mark.asyncio
async def test_summarize_a_real_investigation(
    client: AsyncClient,
    admin_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """`report:summarize` is senior_analyst+; admin outranks it (no senior fixture)."""
    inv = await _seed_case(db_session, sample_user.id, populated=True)

    resp = await client.post(
        "/api/v1/reports/summarize",
        json={"investigation_ids": [inv.id], "format": "cisa"},
        headers=auth_header(admin_token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("status") == "success", body
    # The summary is about this case: its IOC is counted, not the fixture's.
    payload = str(body)
    assert "203.0.113.7" in payload


@pytest.mark.asyncio
async def test_summarize_multiple_real_investigations(
    client: AsyncClient,
    admin_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """The multi-case map-reduce path takes data too, not just the single."""
    first = await _seed_case(db_session, sample_user.id, populated=True)
    second = await _seed_case(db_session, sample_user.id, populated=True)

    resp = await client.post(
        "/api/v1/reports/summarize",
        json={"investigation_ids": [first.id, second.id], "format": "generic"},
        headers=auth_header(admin_token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("status") == "success", body


@pytest.mark.asyncio
async def test_detection_content_for_a_real_investigation(
    client: AsyncClient,
    analyst_token: str,
    sample_user,
    db_session: AsyncSession,
):
    """The fourth endpoint of this shape (#559).

    Missed by #557 because it lives in a module that fix had already touched —
    I fixed the modules I had identified without enumerating every tool inside
    them. `test_every_investigation_route_is_exercised` below makes that
    enumeration mechanical instead of a claim.
    """
    inv = await _seed_case(db_session, sample_user.id, populated=True)

    resp = await client.post(
        "/api/v1/reports/detection-content",
        json={"investigation_id": inv.id, "platform": "splunk"},
        headers=auth_header(analyst_token),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "success"
    assert body["investigation_id"] == inv.id
    # Rules are derived from the case's IOCs, so the seeded indicator has to
    # appear — otherwise the rules describe some other investigation.
    assert "203.0.113.7" in str(body["rules"])


# --------------------------------------------------------------------------- #
# The ratchet
# --------------------------------------------------------------------------- #


def test_every_investigation_route_is_exercised_against_a_real_case():
    """Every reports route taking an investigation id is tested against a row.

    Four endpoints shipped broken in exactly one way — the route scoped
    `investigation_id` against Postgres, then handed the id to a plugin tool
    that resolved the case from a fixture dict. They were fixed in three
    passes (#554, #557, #559) because each pass enumerated by hand and I twice
    stated the set was complete when it was not.

    So the enumeration lives here now. A new endpoint in reports.py that takes
    an investigation id fails this test until it is driven against a real row,
    which is the only check that would have caught any of the four.
    """
    import ast
    from pathlib import Path

    reports_py = (
        Path(__file__).resolve().parent.parent / "btagent_backend" / "api" / "v1" / "reports.py"
    )
    tree = ast.parse(reports_py.read_text(encoding="utf-8"))

    # Route -> the URL path its decorator declares.
    routes: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            if dec.func.attr not in {"get", "post", "put", "patch", "delete"}:
                continue
            if dec.args and isinstance(dec.args[0], ast.Constant):
                routes[node.name] = str(dec.args[0].value)

    # Which of those actually take an investigation id, via a path param or a
    # request model field. Reading the source of the function plus the module
    # keeps this honest for both shapes.
    src = reports_py.read_text(encoding="utf-8")
    takes_investigation = {
        name: path
        for name, path in routes.items()
        if "investigation_id" in src.split(f"def {name}(")[1].split("\n@router")[0]
    }
    assert len(takes_investigation) >= 4, (
        f"only found {len(takes_investigation)} investigation routes; matcher broken?"
    )

    covered = Path(__file__).read_text(encoding="utf-8")
    uncovered = sorted(
        f"{name} ({path})"
        for name, path in takes_investigation.items()
        # The test file drives endpoints by their full URL.
        if f'"/api/v1/reports{path}"' not in covered
        and f"/api/v1/reports{path.split('{')[0]}" not in covered
    )

    assert not uncovered, (
        "These reports endpoints take an investigation id but are never driven "
        "against a real database row in this file, so the failure that broke "
        "four of them would not be caught:\n  " + "\n  ".join(uncovered)
    )
