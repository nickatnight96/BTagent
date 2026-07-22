"""Persistence for advisory hunt packages (#99 / EPIC-2 UC-2.2).

``POST /hunts/package`` generates the artifact; this store makes it durable:
saved on generation, listable newest-first, re-openable by id. Org-scoped
throughout — a package never leaks across tenants. Never commits; the
route's ``get_db`` owns the transaction.
"""

from __future__ import annotations

import logging

from btagent_shared.types.hunt_package import HuntPackage
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import HuntPackageRow

logger = logging.getLogger("btagent.services.hunt_package_store")


async def save_package(
    db: AsyncSession,
    *,
    org_id: str,
    created_by: str | None,
    package: HuntPackage,
) -> HuntPackageRow:
    """Persist a freshly generated package; sets ``package.id`` in place."""
    row_id = generate_id("hpkg")
    package.id = row_id
    row = HuntPackageRow(
        id=row_id,
        org_id=org_id,
        created_by=created_by,
        source_label=package.source_label,
        extracted_ioc_count=package.extracted_ioc_count,
        deduped_count=package.deduped_count,
        techniques=list(package.derived_techniques),
        mock_mode=package.mock_mode,
        package=package.model_dump(mode="json"),
    )
    db.add(row)
    await db.flush()
    logger.info(
        "hunt package %s stored (org=%s, iocs=%d, techniques=%d)",
        row_id,
        org_id,
        package.extracted_ioc_count,
        len(package.derived_techniques),
    )
    return row


async def list_packages(
    db: AsyncSession,
    *,
    org_id: str,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[HuntPackageRow], int]:
    """Org-scoped package history, newest first."""
    count_q = (
        select(func.count()).select_from(HuntPackageRow).where(HuntPackageRow.org_id == org_id)
    )
    total = (await db.execute(count_q)).scalar_one() or 0

    rows_q = (
        select(HuntPackageRow)
        .where(HuntPackageRow.org_id == org_id)
        .order_by(HuntPackageRow.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(rows_q)).scalars().all()
    return list(rows), int(total)


async def link_investigation(
    db: AsyncSession, *, row: HuntPackageRow, investigation_id: str
) -> None:
    """Record package → case lineage after a promote (flush, no commit)."""
    row.investigation_id = investigation_id
    await db.flush()
    logger.info("hunt package %s promoted to investigation %s", row.id, investigation_id)


async def get_package(db: AsyncSession, *, org_id: str, package_id: str) -> HuntPackageRow | None:
    """Fetch one package; ``None`` on miss OR cross-org access (route 404s)."""
    result = await db.execute(
        select(HuntPackageRow).where(
            HuntPackageRow.id == package_id,
            HuntPackageRow.org_id == org_id,
        )
    )
    return result.scalar_one_or_none()
