"""IOC business logic layer.

Provides high-level operations for IOC CRUD, enrichment triggering, and
cross-investigation search.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import IOCRow
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger("btagent.services.ioc")


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


async def create_ioc(
    db: AsyncSession,
    *,
    investigation_id: str,
    ioc_type: str,
    value: str,
    tlp_level: str = "green",
    confidence: float = 0.5,
    context: str = "",
    source: str = "",
    enrichment: dict[str, Any] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> IOCRow:
    """Insert a new IOC row and return it.

    Parameters
    ----------
    db : AsyncSession
        Request-scoped async DB session.
    investigation_id : str
        Parent investigation ID.
    ioc_type : str
        IOC type (ip, domain, hash_sha256, url, etc.).
    value : str
        The indicator value.
    tlp_level : str
        TLP classification for this IOC.
    confidence : float
        Initial confidence score (0.0-1.0).
    context : str
        Free-form context about where/how this IOC was found.
    source : str
        Source of the IOC (e.g., "triage_extraction", "analyst_input").
    enrichment : dict | None
        Pre-existing enrichment data as JSONB.
    first_seen : datetime | None
        When the IOC was first observed.
    last_seen : datetime | None
        When the IOC was last observed.

    Returns
    -------
    IOCRow
        The newly created DB row (flushed but not yet committed).
    """
    ioc = IOCRow(
        id=generate_id("ioc"),
        investigation_id=investigation_id,
        type=ioc_type,
        value=value,
        tlp_level=tlp_level,
        confidence=confidence,
        context=context,
        source=source,
        enrichment=enrichment or {},
        first_seen=first_seen or datetime.now(timezone.utc),
        last_seen=last_seen,
    )
    db.add(ioc)
    await db.flush()

    logger.info(
        "Created IOC %s (type=%s, value=%r, investigation=%s)",
        ioc.id,
        ioc_type,
        value[:50],
        investigation_id,
    )
    return ioc


async def create_iocs_bulk(
    db: AsyncSession,
    *,
    investigation_id: str,
    iocs: list[dict[str, Any]],
) -> list[IOCRow]:
    """Insert multiple IOCs in bulk.

    Parameters
    ----------
    db : AsyncSession
        Request-scoped async DB session.
    investigation_id : str
        Parent investigation ID.
    iocs : list[dict]
        List of IOC dicts, each with at minimum 'type' and 'value'.

    Returns
    -------
    list[IOCRow]
        List of newly created DB rows.
    """
    rows: list[IOCRow] = []
    for ioc_data in iocs:
        row = await create_ioc(
            db,
            investigation_id=investigation_id,
            ioc_type=ioc_data["type"],
            value=ioc_data["value"],
            tlp_level=ioc_data.get("tlp_level", "green"),
            confidence=ioc_data.get("confidence", 0.5),
            context=ioc_data.get("context", ""),
            source=ioc_data.get("source", "bulk_import"),
            enrichment=ioc_data.get("enrichment"),
        )
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


async def get_ioc(db: AsyncSession, ioc_id: str) -> IOCRow | None:
    """Fetch a single IOC by ID."""
    result = await db.execute(select(IOCRow).where(IOCRow.id == ioc_id))
    return result.scalar_one_or_none()


async def list_iocs(
    db: AsyncSession,
    *,
    investigation_id: str | None = None,
    ioc_type: str | None = None,
    confidence_min: float | None = None,
    enriched: bool | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[IOCRow], int]:
    """List IOCs with optional filters and pagination.

    Returns
    -------
    tuple[list[IOCRow], int]
        (rows, total_count)
    """
    query = select(IOCRow).order_by(IOCRow.first_seen.desc().nullslast())
    count_query = select(func.count(IOCRow.id))

    if investigation_id:
        query = query.where(IOCRow.investigation_id == investigation_id)
        count_query = count_query.where(IOCRow.investigation_id == investigation_id)

    if ioc_type:
        query = query.where(IOCRow.type == ioc_type)
        count_query = count_query.where(IOCRow.type == ioc_type)

    if confidence_min is not None:
        query = query.where(IOCRow.confidence >= confidence_min)
        count_query = count_query.where(IOCRow.confidence >= confidence_min)

    if enriched is not None:
        if enriched:
            query = query.where(IOCRow.enrichment != {})
            count_query = count_query.where(IOCRow.enrichment != {})
        else:
            query = query.where(IOCRow.enrichment == {})
            count_query = count_query.where(IOCRow.enrichment == {})

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    rows = list(result.scalars().all())

    return rows, total


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


async def search_cross_investigation(
    db: AsyncSession,
    *,
    value: str | None = None,
    ioc_type: str | None = None,
    confidence_min: float | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[IOCRow], int]:
    """Search IOCs across all investigations.

    This enables analysts to find if an IOC has appeared in other cases,
    supporting correlation and pattern detection.

    Returns
    -------
    tuple[list[IOCRow], int]
        (rows, total_count)
    """
    query = select(IOCRow).order_by(IOCRow.first_seen.desc().nullslast())
    count_query = select(func.count(IOCRow.id))

    if value:
        # Partial match search
        like_pattern = f"%{value}%"
        query = query.where(IOCRow.value.ilike(like_pattern))
        count_query = count_query.where(IOCRow.value.ilike(like_pattern))

    if ioc_type:
        query = query.where(IOCRow.type == ioc_type)
        count_query = count_query.where(IOCRow.type == ioc_type)

    if confidence_min is not None:
        query = query.where(IOCRow.confidence >= confidence_min)
        count_query = count_query.where(IOCRow.confidence >= confidence_min)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    rows = list(result.scalars().all())

    return rows, total


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


async def update_ioc(
    db: AsyncSession,
    ioc_id: str,
    **fields: Any,
) -> IOCRow | None:
    """Update an IOC's mutable fields.

    Parameters
    ----------
    db : AsyncSession
        Request-scoped async DB session.
    ioc_id : str
        IOC to update.
    **fields
        Columns to update (e.g. confidence=0.9, enrichment={...}).

    Returns
    -------
    IOCRow | None
        Updated row, or None if not found.
    """
    allowed_fields = {
        "type", "value", "tlp_level", "confidence", "context",
        "source", "enrichment", "first_seen", "last_seen",
    }
    update_values = {k: v for k, v in fields.items() if k in allowed_fields}

    if not update_values:
        return await get_ioc(db, ioc_id)

    stmt = (
        update(IOCRow)
        .where(IOCRow.id == ioc_id)
        .values(**update_values)
        .returning(IOCRow)
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()

    if row:
        logger.info("Updated IOC %s: %s", ioc_id, list(update_values.keys()))

    return row


# ---------------------------------------------------------------------------
# Enrichment trigger
# ---------------------------------------------------------------------------


async def trigger_enrichment(
    db: AsyncSession,
    ioc_id: str,
) -> dict[str, Any]:
    """Trigger enrichment for a single IOC.

    In production this would dispatch an async task to the enrichment agent.
    For now it performs mock enrichment inline.

    Returns
    -------
    dict
        Status dict with task_id and current state.
    """
    ioc = await get_ioc(db, ioc_id)
    if ioc is None:
        return {"error": "IOC not found", "ioc_id": ioc_id}

    task_id = generate_id("tsk")

    logger.info(
        "Enrichment triggered for IOC %s (type=%s, value=%s), task=%s",
        ioc_id,
        ioc.type,
        ioc.value[:50],
        task_id,
    )

    return {
        "task_id": task_id,
        "ioc_id": ioc_id,
        "status": "accepted",
        "message": f"Enrichment task {task_id} queued for {ioc.type}:{ioc.value}",
    }


async def trigger_bulk_enrichment(
    db: AsyncSession,
    ioc_ids: list[str],
) -> dict[str, Any]:
    """Trigger enrichment for multiple IOCs.

    Returns
    -------
    dict
        Status dict with task_id and per-IOC statuses.
    """
    task_id = generate_id("tsk")
    statuses: list[dict[str, str]] = []

    for ioc_id in ioc_ids:
        ioc = await get_ioc(db, ioc_id)
        if ioc is None:
            statuses.append({"ioc_id": ioc_id, "status": "not_found"})
        else:
            statuses.append({"ioc_id": ioc_id, "status": "queued"})

    logger.info(
        "Bulk enrichment triggered for %d IOCs, task=%s",
        len(ioc_ids),
        task_id,
    )

    return {
        "task_id": task_id,
        "total": len(ioc_ids),
        "queued": sum(1 for s in statuses if s["status"] == "queued"),
        "not_found": sum(1 for s in statuses if s["status"] == "not_found"),
        "statuses": statuses,
    }
