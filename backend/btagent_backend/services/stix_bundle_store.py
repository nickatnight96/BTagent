"""STIX bundle store — persist raw bundles for bundle-by-id reprocessing (#113).

Backs the ``stix_bundle_id`` path of ``POST /cti/propose-detections``: the raw
path stores its bundle here (keyed by the bundle's own STIX id), and a later
request resolves it by id instead of re-uploading. Upsert semantics — re-storing
the same ``(org_id, bundle_id)`` refreshes the stored copy.

Like the other store helpers, neither function commits — the ``get_db``
dependency owns the commit on request success.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_cti import StixBundleRow

logger = logging.getLogger("btagent.services.stix_bundle_store")


async def store_bundle(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    bundle: dict[str, Any],
    tlp: str = "green",
) -> StixBundleRow | None:
    """Persist (upsert) a STIX bundle by its own id; returns the row.

    Bundles with no ``id`` are ad-hoc and cannot be resolved later, so they are
    skipped (returns ``None``). Does not commit — the caller owns that.
    """
    bundle_id = bundle.get("id") if isinstance(bundle, dict) else None
    if not bundle_id:
        return None

    existing = (
        await db.execute(
            select(StixBundleRow).where(
                StixBundleRow.org_id == org_id,
                StixBundleRow.bundle_id == bundle_id,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.bundle = bundle
        existing.tlp = tlp
        await db.flush()
        return existing

    row = StixBundleRow(
        id=generate_id("stixb"),
        org_id=org_id,
        bundle_id=bundle_id,
        bundle=bundle,
        tlp=tlp,
    )
    db.add(row)
    await db.flush()
    logger.info("stored STIX bundle %s (org=%s)", bundle_id, org_id)
    return row


async def get_bundle(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    bundle_id: str,
) -> dict[str, Any] | None:
    """Return the stored bundle dict for ``(org_id, bundle_id)``, or ``None``."""
    row = (
        await db.execute(
            select(StixBundleRow).where(
                StixBundleRow.org_id == org_id,
                StixBundleRow.bundle_id == bundle_id,
            )
        )
    ).scalar_one_or_none()
    return dict(row.bundle) if row is not None else None
