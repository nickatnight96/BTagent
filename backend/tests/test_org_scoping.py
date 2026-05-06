"""Org scoping schema tests.

Phase A1 of the auth-hardening milestone introduces an ``organizations``
table and an ``org_id`` foreign key on the four core resource tables.
This file pins the structural invariants so future migrations can't
quietly regress them.

Route-level org scoping (filtering reads/writes by caller's org_id) is
Phase B1's responsibility and is tested separately.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import PREFIXES, generate_id
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import (
    InvestigationRow,
    OrganizationRow,
    UserRow,
)


@pytest.mark.asyncio
async def test_default_org_seeded_after_init(db_session: AsyncSession):
    """The ``_init_db`` fixture seeds ``org_default`` so other fixtures
    can satisfy the new FK without having to create an org first."""
    org = await db_session.get(OrganizationRow, "org_default")
    assert org is not None
    assert org.name == "Default Organization"


def test_org_id_prefix_registered():
    """``shared/btagent_shared/utils/ids.py`` must know about the new
    ``org_`` prefix so callers can ``generate_id("org")`` without
    raising."""
    assert "org" in PREFIXES
    new_id = generate_id("org")
    assert new_id.startswith("org_")


@pytest.mark.asyncio
async def test_user_inherits_default_org_when_unspecified(
    db_session: AsyncSession,
):
    """``UserRow.org_id`` has a Python-level default of ``"org_default"``,
    so callers that pre-date Phase A1 keep working without explicit
    org assignment. They land in the default org."""
    user = UserRow(
        id=generate_id("usr"),
        username="default_org_user",
        email="defaultorg@example.test",
        password_hash="hashed",
        role="analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()

    result = await db_session.execute(select(UserRow).where(UserRow.id == user.id))
    fetched = result.scalar_one()
    assert fetched.org_id == "org_default"


@pytest.mark.asyncio
async def test_investigation_org_id_is_not_nullable(db_session: AsyncSession):
    """Bypassing the Python default and forcing ``org_id=None`` must
    fail at flush time -- the column is NOT NULL at the DB level."""
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=None,  # type: ignore[arg-type]
        title="No Org",
        description="this should not commit",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.LOW.value,
        tlp_level="green",
        assigned_to=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_investigation_org_id_must_reference_existing_org(
    db_session: AsyncSession,
):
    """Pointing at a non-existent org_id violates the FK constraint."""
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id="org_does_not_exist",
        title="Bogus Org",
        description="missing FK target",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.LOW.value,
        tlp_level="green",
        assigned_to=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_user_delete_sets_investigation_assigned_to_null(
    db_session: AsyncSession,
    sample_user: UserRow,
):
    """The migration tightens the ``assigned_to`` FK with ``ON DELETE
    SET NULL``. Deleting a user must leave their investigations intact
    with ``assigned_to`` cleared, not orphaned or cascading-deleted."""
    inv = InvestigationRow(
        id=generate_id("inv"),
        title="Owned Investigation",
        description="will be orphaned by user delete",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.MEDIUM.value,
        tlp_level="green",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()
    inv_id = inv.id

    await db_session.delete(sample_user)
    await db_session.commit()

    refreshed = await db_session.get(InvestigationRow, inv_id)
    assert refreshed is not None, "Investigation must survive user deletion"
    assert refreshed.assigned_to is None, "assigned_to must be set NULL by the FK ondelete rule"
