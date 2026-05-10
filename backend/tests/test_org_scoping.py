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


def test_investigation_org_id_is_not_nullable():
    """The column declares ``nullable=False`` so the migration enforces
    NOT NULL at the DB level. Asserting at the schema level rather than
    runtime because the column also has a Python-level
    ``default="org_default"`` -- passing ``org_id=None`` triggers the
    default, so the runtime path can't actually produce a NULL insert."""
    col = InvestigationRow.__table__.c.org_id
    assert col.nullable is False
    # Sanity check: the FK target is what the migration says it is.
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert str(fks[0].column) == "organizations.id"


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


def test_assigned_to_fk_has_set_null_ondelete():
    """The migration tightens the ``assigned_to`` FK with ``ON DELETE
    SET NULL``. Asserting at the schema level rather than via runtime
    delete because SQLite's session cache + the way SQLAlchemy materialises
    deletes makes the runtime cascade flaky in unit tests; production
    Postgres + the migration handle the actual delete-cascade."""
    col = InvestigationRow.__table__.c.assigned_to
    fks = list(col.foreign_keys)
    assert len(fks) == 1, "assigned_to should have exactly one FK"
    fk = fks[0]
    assert str(fk.column) == "users.id"
    assert fk.ondelete == "SET NULL"
