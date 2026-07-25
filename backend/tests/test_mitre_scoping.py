"""Regression tests for MITRE coverage/tag org-scoping (GH #375).

Before the fix, the coverage / score / gaps / navigator-export routes passed an
arbitrary ``investigation_id`` straight to the service (which filtered only by
investigation_id, never org), and ``/mitre/tag`` wrote a tag onto any
caller-supplied ``entity_id`` with no org check. These tests pin the fix:

  * a cross-org ``investigation_id`` 404s (existence-oracle policy — not 403);
  * a non-existent ``investigation_id`` 404s;
  * own-org / global reads still succeed;
  * ``/mitre/tag`` refuses (404) to tag an entity in another tenant and does
    not write a row, while an own-org tag succeeds.
"""

from __future__ import annotations

from datetime import UTC, datetime

from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    InvestigationRow,
    IOCRow,
    OrganizationRow,
)
from btagent_backend.db.models_mitre import MitreTechniqueRow, MitreTechniqueTagRow
from tests.helpers import auth_header

_OTHER_ORG = "org_mitre_other_tenant"


async def _make_org(db_session: AsyncSession, org_id: str) -> OrganizationRow:
    org = await db_session.get(OrganizationRow, org_id)
    if org is None:
        org = OrganizationRow(id=org_id, name=f"Org {org_id}")
        db_session.add(org)
        await db_session.commit()
    return org


async def _make_investigation(
    db_session: AsyncSession, *, org_id: str, owner_id: str | None = None
) -> InvestigationRow:
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=org_id,
        title="Mitre scoping test",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=owner_id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()
    return inv


async def _make_ioc(db_session: AsyncSession, *, org_id: str, investigation_id: str) -> IOCRow:
    ioc = IOCRow(
        id=generate_id("ioc"),
        org_id=org_id,
        investigation_id=investigation_id,
        type="ip",
        value="203.0.113.7",
    )
    db_session.add(ioc)
    await db_session.commit()
    return ioc


# --- Coverage / score / gaps / export: cross-org investigation_id => 404 --- #


async def test_coverage_cross_org_investigation_is_404(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession
):
    await _make_org(db_session, _OTHER_ORG)
    other_inv = await _make_investigation(db_session, org_id=_OTHER_ORG)

    for path in ("coverage", "coverage/score", "gaps", "export/navigator"):
        resp = await client.get(
            f"/api/v1/mitre/{path}?investigation_id={other_inv.id}",
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 404, f"{path}: {resp.status_code} {resp.text}"


async def test_coverage_unknown_investigation_is_404(client: AsyncClient, analyst_token: str):
    resp = await client.get(
        "/api/v1/mitre/coverage?investigation_id=inv_does_not_exist",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


async def test_coverage_own_investigation_ok(
    client: AsyncClient, analyst_token: str, sample_investigation: InvestigationRow
):
    resp = await client.get(
        f"/api/v1/mitre/coverage?investigation_id={sample_investigation.id}",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text


async def test_coverage_global_view_ok(client: AsyncClient, analyst_token: str):
    # No investigation_id -> org-scoped global aggregation, still a 200.
    resp = await client.get("/api/v1/mitre/coverage", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text


# --- Tagging: cross-org entity => 404 + no write; own-org => 201 ----------- #


async def test_tag_cross_org_entity_is_404_and_writes_nothing(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    await _make_org(db_session, _OTHER_ORG)
    other_inv = await _make_investigation(db_session, org_id=_OTHER_ORG)
    other_ioc = await _make_ioc(db_session, org_id=_OTHER_ORG, investigation_id=other_inv.id)

    resp = await client.post(
        "/api/v1/mitre/tag",
        headers=auth_header(admin_token),
        json={
            "entity_type": "ioc",
            "entity_id": other_ioc.id,
            "technique_id": "T1059",
            "confidence": 0.9,
        },
    )
    assert resp.status_code == 404, resp.text

    # The cross-org write must have been refused BEFORE any row was inserted.
    count = (
        await db_session.execute(
            select(func.count())
            .select_from(MitreTechniqueTagRow)
            .where(MitreTechniqueTagRow.entity_id == other_ioc.id)
        )
    ).scalar_one()
    assert count == 0


async def test_tag_unknown_entity_type_is_404(client: AsyncClient, admin_token: str):
    # No investigation linkage to verify ownership -> fail closed.
    resp = await client.post(
        "/api/v1/mitre/tag",
        headers=auth_header(admin_token),
        json={
            "entity_type": "alert",
            "entity_id": "alert_whatever",
            "technique_id": "T1059",
        },
    )
    assert resp.status_code == 404, resp.text


async def test_tag_own_org_entity_ok(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    # Technique row must exist (tag FK -> mitre_techniques.id).
    if (await db_session.get(MitreTechniqueRow, "T1059")) is None:
        db_session.add(
            MitreTechniqueRow(
                id="T1059", name="Command and Scripting Interpreter", tactic="execution"
            )
        )
        await db_session.commit()

    inv = await _make_investigation(db_session, org_id=DEFAULT_ORG_ID)
    ioc = await _make_ioc(db_session, org_id=DEFAULT_ORG_ID, investigation_id=inv.id)

    resp = await client.post(
        "/api/v1/mitre/tag",
        headers=auth_header(admin_token),
        json={
            "entity_type": "ioc",
            "entity_id": ioc.id,
            "technique_id": "T1059",
            "confidence": 0.75,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["entity_id"] == ioc.id
    assert body["technique_id"] == "T1059"
