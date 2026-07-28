"""``mitre_tags`` on the IOC detail response — the read side the panel assumed.

The IOC detail panel has rendered a "MITRE ATT&CK Techniques" section from
``selectedIOC.mitre_tags`` since it shipped — and no backend code ever
populated that field, so the section had never once rendered. Wiring the tag
*write* path (``POST /mitre/tag``, the last MITRE ratchet gap with a buildable
UI) exposed the fiction on the read side: without this, a senior analyst's
tag would 201 and then be invisible everywhere.

The shape matches the frontend's long-standing ``MitreTag`` type
(``technique_id`` / ``technique_name`` / ``tactic``) plus ``confidence``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow, IOCRow, UserRow
from btagent_backend.db.models_mitre import MitreTechniqueRow, MitreTechniqueTagRow
from tests.helpers import auth_header

_TECHNIQUE_ID = "T1566"


async def _ioc_for_analyst(db_session: AsyncSession, analyst: UserRow) -> IOCRow:
    """An IOC whose investigation is assigned to ``analyst``.

    Analyst-role reads require ``assigned_to == user.id`` (scoping.py), so an
    unassigned investigation 404s for the analyst token — correct behaviour,
    but not what these read-path tests are about.
    """
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="IOC mitre-tag read test",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=analyst.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)

    ioc = IOCRow(
        id=generate_id("ioc"),
        org_id=DEFAULT_ORG_ID,
        investigation_id=inv.id,
        type="ip",
        value="198.51.100.99",
    )
    db_session.add(ioc)
    await db_session.commit()
    return ioc


@pytest_asyncio.fixture()
async def sample_ioc(db_session: AsyncSession, sample_user: UserRow) -> IOCRow:
    """An untagged IOC readable by the analyst token."""
    return await _ioc_for_analyst(db_session, sample_user)


@pytest_asyncio.fixture()
async def tagged_ioc(db_session: AsyncSession, sample_user: UserRow) -> IOCRow:
    """An own-org IOC with one named-technique tag and one unresolvable tag."""
    ioc = await _ioc_for_analyst(db_session, sample_user)

    if await db_session.get(MitreTechniqueRow, _TECHNIQUE_ID) is None:
        db_session.add(
            MitreTechniqueRow(
                id=_TECHNIQUE_ID,
                name="Phishing",
                tactic="initial-access",
            )
        )

    db_session.add(
        MitreTechniqueTagRow(
            id=generate_id("mtag"),
            entity_type="ioc",
            entity_id=ioc.id,
            technique_id=_TECHNIQUE_ID,
            confidence=0.8,
            tagged_by="usr_senior",
        )
    )
    # A tag whose technique is not in the loaded matrix. It must still
    # surface — hiding an existing tag is worse than showing it unnamed —
    # but there is no FK-satisfiable way to write an unknown technique_id,
    # so it references a second, minimal technique row with blank-ish data.
    if await db_session.get(MitreTechniqueRow, "T9999") is None:
        db_session.add(MitreTechniqueRow(id="T9999", name="T9999", tactic=""))
    db_session.add(
        MitreTechniqueTagRow(
            id=generate_id("mtag"),
            entity_type="ioc",
            entity_id=ioc.id,
            technique_id="T9999",
            confidence=0.3,
            tagged_by="usr_senior",
        )
    )
    await db_session.commit()
    return ioc


async def test_detail_returns_tags_with_names_resolved(
    client: AsyncClient, analyst_token: str, tagged_ioc: IOCRow
):
    resp = await client.get(f"/api/v1/iocs/{tagged_ioc.id}", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text

    tags = {t["technique_id"]: t for t in resp.json()["mitre_tags"]}
    assert _TECHNIQUE_ID in tags
    assert tags[_TECHNIQUE_ID]["technique_name"] == "Phishing"
    assert tags[_TECHNIQUE_ID]["tactic"] == "initial-access"
    assert tags[_TECHNIQUE_ID]["confidence"] == 0.8


async def test_untagged_ioc_returns_an_empty_list_not_a_missing_field(
    client: AsyncClient, analyst_token: str, sample_ioc: IOCRow
):
    """The field is always present so the panel can rely on it."""
    resp = await client.get(f"/api/v1/iocs/{sample_ioc.id}", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    assert resp.json()["mitre_tags"] == []


async def test_tag_written_through_the_endpoint_round_trips(
    client: AsyncClient,
    admin_token: str,
    analyst_token: str,
    sample_ioc: IOCRow,
    db_session: AsyncSession,
):
    """The whole point of the slice: POST /mitre/tag → visible on the IOC.

    Without the read side, a senior analyst's tag returned 201 and then
    appeared nowhere in the product.
    """
    # The tag FKs mitre_techniques; seed the row here rather than relying on
    # another test's fixture having run first (this suite runs randomised).
    if await db_session.get(MitreTechniqueRow, _TECHNIQUE_ID) is None:
        db_session.add(
            MitreTechniqueRow(id=_TECHNIQUE_ID, name="Phishing", tactic="initial-access")
        )
        await db_session.commit()

    created = await client.post(
        "/api/v1/mitre/tag",
        headers=auth_header(admin_token),
        json={
            "entity_type": "ioc",
            "entity_id": sample_ioc.id,
            "technique_id": _TECHNIQUE_ID,
            "confidence": 0.65,
        },
    )
    assert created.status_code == 201, created.text

    resp = await client.get(f"/api/v1/iocs/{sample_ioc.id}", headers=auth_header(analyst_token))
    tags = {t["technique_id"]: t for t in resp.json()["mitre_tags"]}
    assert _TECHNIQUE_ID in tags
    assert tags[_TECHNIQUE_ID]["confidence"] == 0.65
