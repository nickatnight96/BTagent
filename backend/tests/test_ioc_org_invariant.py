"""An IOC's ``org_id`` is its parent investigation's, structurally.

``IOCRow.org_id`` is not independent data — it is a denormalised copy of the
parent investigation's tenant, kept so a single IOC can be scoped without a
join. ``assert_can_access_ioc`` trusts that copy: when no parent row is passed
it decides purely on ``ioc.org_id == user.org_id``. So an IOC whose org drifted
from its investigation's is readable by the wrong tenant's org-wide roles, and
*un*readable by the right tenant's.

Nothing enforced it. ``create_ioc``/``create_iocs_bulk`` took ``org_id`` as an
optional argument that fell back to the column default (``org_default``), so a
caller who omitted it stamped IOCs with a tenant unrelated to the parent case.

**No live path did that** — all six call sites passed a value, five as
``inv.org_id`` and the TAXII poller as ``feed.org_id`` (equal by construction:
the intake investigation is fetched with ``org_id == feed.org_id``). This is
not a leak that happened; it is a convention six call sites happened to keep,
promoted to an invariant the service enforces.

The tests below drive the real service against a real session, because the
property is about what lands in the database, not about what the source says.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow, IOCRow, OrganizationRow
from btagent_backend.services import ioc_service

_OTHER_ORG = "org_ioc_invariant"


@pytest_asyncio.fixture()
async def foreign_investigation(db_session: AsyncSession) -> InvestigationRow:
    """An investigation deliberately *not* in the default org.

    The default org is what an omitted ``org_id`` used to fall back to, so a
    parent outside it is what makes the drift visible at all.
    """
    if await db_session.get(OrganizationRow, _OTHER_ORG) is None:
        db_session.add(
            OrganizationRow(id=_OTHER_ORG, name=_OTHER_ORG, created_at=datetime.now(UTC))
        )
        await db_session.commit()

    inv = InvestigationRow(
        id=generate_id("inv"),
        title="Foreign-tenant case",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity="medium",
        tlp_level="green",
        org_id=_OTHER_ORG,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()
    return inv


@pytest.mark.asyncio
async def test_single_create_inherits_the_parents_org_without_being_told(
    db_session: AsyncSession, foreign_investigation: InvestigationRow
):
    """The regression: omitting org_id used to stamp `org_default`."""
    ioc = await ioc_service.create_ioc(
        db_session,
        investigation_id=foreign_investigation.id,
        ioc_type="ip",
        value="10.10.10.1",
    )
    assert ioc.org_id == _OTHER_ORG
    assert ioc.org_id != DEFAULT_ORG_ID, "IOC fell back to the default org"


@pytest.mark.asyncio
async def test_bulk_create_inherits_the_parents_org_without_being_told(
    db_session: AsyncSession, foreign_investigation: InvestigationRow
):
    rows = await ioc_service.create_iocs_bulk(
        db_session,
        investigation_id=foreign_investigation.id,
        iocs=[{"type": "ip", "value": "10.10.10.2"}, {"type": "domain", "value": "evil.test"}],
    )
    assert len(rows) == 2
    assert {r.org_id for r in rows} == {_OTHER_ORG}


@pytest.mark.asyncio
async def test_a_mismatched_org_id_is_refused_not_trusted(
    db_session: AsyncSession, foreign_investigation: InvestigationRow
):
    """Passing the wrong tenant must fail loudly, not write a mis-stamped row.

    This is the shape a future caller would get wrong: reaching for some org
    id in scope (a feed's, a user's) that is not the parent case's.
    """
    with pytest.raises(ValueError, match="does not match investigation"):
        await ioc_service.create_ioc(
            db_session,
            investigation_id=foreign_investigation.id,
            ioc_type="ip",
            value="10.10.10.3",
            org_id=DEFAULT_ORG_ID,
        )


@pytest.mark.asyncio
async def test_bulk_rejects_a_mismatched_org_id_before_writing_anything(
    db_session: AsyncSession, foreign_investigation: InvestigationRow
):
    """The check must precede the inserts, or a partial batch lands."""
    before = len(
        (
            await db_session.execute(
                select(IOCRow).where(IOCRow.investigation_id == foreign_investigation.id)
            )
        )
        .scalars()
        .all()
    )
    with pytest.raises(ValueError, match="does not match investigation"):
        await ioc_service.create_iocs_bulk(
            db_session,
            investigation_id=foreign_investigation.id,
            iocs=[{"type": "ip", "value": "10.10.10.4"}],
            org_id=DEFAULT_ORG_ID,
        )
    after = len(
        (
            await db_session.execute(
                select(IOCRow).where(IOCRow.investigation_id == foreign_investigation.id)
            )
        )
        .scalars()
        .all()
    )
    assert after == before, "a rejected bulk create still wrote rows"


@pytest.mark.asyncio
async def test_matching_org_id_is_still_accepted(
    db_session: AsyncSession, foreign_investigation: InvestigationRow
):
    """Existing callers pass the right value; they must keep working."""
    ioc = await ioc_service.create_ioc(
        db_session,
        investigation_id=foreign_investigation.id,
        ioc_type="ip",
        value="10.10.10.5",
        org_id=foreign_investigation.org_id,
    )
    assert ioc.org_id == _OTHER_ORG


@pytest.mark.asyncio
async def test_unknown_parent_is_a_clear_error_not_an_orphan(db_session: AsyncSession):
    """The FK would reject it later; this names the actual problem."""
    with pytest.raises(ValueError, match="unknown investigation"):
        await ioc_service.create_ioc(
            db_session,
            investigation_id="inv_does_not_exist",
            ioc_type="ip",
            value="10.10.10.6",
        )


@pytest.mark.asyncio
async def test_bulk_resolves_the_parent_org_once_not_per_row(
    db_session: AsyncSession, foreign_investigation: InvestigationRow, monkeypatch
):
    """An import can carry hundreds of IOCs that all share one parent.

    Guarding this because the obvious implementation — bulk looping the single
    create — reintroduces N identical lookups, and nothing else would notice.
    """
    calls = 0
    original = ioc_service._org_of_investigation

    async def counting(db, investigation_id):  # noqa: ANN001, ANN202
        nonlocal calls
        calls += 1
        return await original(db, investigation_id)

    monkeypatch.setattr(ioc_service, "_org_of_investigation", counting)

    await ioc_service.create_iocs_bulk(
        db_session,
        investigation_id=foreign_investigation.id,
        iocs=[{"type": "ip", "value": f"10.20.0.{i}"} for i in range(25)],
    )
    assert calls == 1, f"resolved the parent org {calls} times for one batch"


@pytest.mark.asyncio
async def test_every_stored_ioc_agrees_with_its_parent(
    db_session: AsyncSession, foreign_investigation: InvestigationRow
):
    """The invariant itself, checked against the rows rather than the code."""
    await ioc_service.create_iocs_bulk(
        db_session,
        investigation_id=foreign_investigation.id,
        iocs=[{"type": "ip", "value": "10.30.0.1"}],
    )
    await db_session.commit()

    mismatched = (
        await db_session.execute(
            select(IOCRow.id, IOCRow.org_id, InvestigationRow.org_id)
            .join(InvestigationRow, IOCRow.investigation_id == InvestigationRow.id)
            .where(IOCRow.org_id != InvestigationRow.org_id)
        )
    ).all()
    assert not mismatched, f"IOC(s) whose org differs from their parent case: {mismatched}"
