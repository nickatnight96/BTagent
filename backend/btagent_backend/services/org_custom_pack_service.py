"""Org-authored hunt-pack bundles (#112 slice 2).

The store behind ``/hunt/custom-packs``: an org uploads a pack as content
(pack.yaml text + rule files), the bundle is validated through the engine's
``load_pack_from_bundle`` — the SAME loader the builtin directory packs go
through, so an uploaded pack passes exactly the checks a shipped pack passes
and keeps deterministic ids — and the verbatim content is persisted. The
scheduled sweep re-loads each row through that loader on every run
(:mod:`btagent_backend.services.hunt_pack_run_service`), so a row that
persists is a row that runs.

Design points:

* **Validate-then-store, verbatim.** Nothing derived is persisted except the
  identity fields the catalog and run history need (pack_id/name/version/
  rule_count); the source of truth stays the uploaded YAML.
* **Upsert on (org, pack_id).** Re-uploading the same pack identity (same
  manifest id, or same name+version when the id is derived) updates in
  place — run history and the noise baseline keep correlating on one id.
* **Enabled-by-existence.** Delete removes the pack from the sweep; there is
  no separate disable state to drift in this slice.
* **Builtin collisions refused.** A custom pack whose id matches a builtin
  manifest id would make run history ambiguous; the upload is rejected.

Org-scoped at every query; flushes but never commits (the route owns the
transaction), matching the rest of the hunt services.
"""

from __future__ import annotations

import logging

from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import OrgCustomPackRow

logger = logging.getLogger("btagent.services.org_custom_packs")

#: Hard cap on bundle size, mirroring the strictest upload surfaces: a pack
#: is rule text, not an archive dump.
MAX_RULE_FILES = 100
MAX_TOTAL_BYTES = 1_000_000


class InvalidPackBundle(ValueError):
    """Upload failed validation (route → 422)."""


def _load_bundle(manifest_yaml: str, rule_files: dict[str, str]):
    """Validate through the engine loader; translate errors to the API shape."""
    # Lazy: the engine pulls pysigma, only present in the worker image.
    from btagent_engine.hunting.pack import PackLoadError, load_pack_from_bundle

    total = len(manifest_yaml.encode()) + sum(len(v.encode()) for v in rule_files.values())
    if len(rule_files) > MAX_RULE_FILES:
        raise InvalidPackBundle(f"too many rule files (max {MAX_RULE_FILES})")
    if total > MAX_TOTAL_BYTES:
        raise InvalidPackBundle(f"bundle too large (max {MAX_TOTAL_BYTES} bytes)")
    try:
        return load_pack_from_bundle(manifest_yaml, rule_files)
    except PackLoadError as exc:
        raise InvalidPackBundle(str(exc)) from exc


def _builtin_manifest_ids() -> set[str]:
    from btagent_backend.services.hunt_pack_store import list_builtin_packs

    return {p.manifest_pack_id for p in list_builtin_packs()}


async def create_or_update_pack(
    db: AsyncSession,
    *,
    org_id: str,
    manifest_yaml: str,
    rule_files: dict[str, str],
    created_by: str | None = None,
) -> tuple[OrgCustomPackRow, bool]:
    """Validate a bundle and persist it; returns ``(row, created)``.

    ``created`` is False when the upload matched an existing (org, pack_id)
    row and updated it in place.
    """
    pack = _load_bundle(manifest_yaml, rule_files)
    if pack.id in _builtin_manifest_ids():
        raise InvalidPackBundle(
            f"pack id {pack.id!r} collides with a builtin pack; give the custom "
            "pack its own id (or name/version) so run history stays unambiguous"
        )

    existing = (
        await db.execute(
            select(OrgCustomPackRow).where(
                OrgCustomPackRow.org_id == org_id,
                OrgCustomPackRow.pack_id == pack.id,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.name = pack.name
        existing.version = pack.version
        existing.description = pack.description
        existing.manifest_yaml = manifest_yaml
        existing.rule_files = dict(rule_files)
        existing.rule_count = len(pack.rules)
        existing.created_by = created_by or existing.created_by
        await db.flush()
        logger.info("custom pack updated org=%s pack=%s", org_id, pack.id)
        return existing, False

    row = OrgCustomPackRow(
        id=generate_id("ocp"),
        org_id=org_id,
        pack_id=pack.id,
        name=pack.name,
        version=pack.version,
        description=pack.description,
        manifest_yaml=manifest_yaml,
        rule_files=dict(rule_files),
        rule_count=len(pack.rules),
        created_by=created_by,
    )
    db.add(row)
    await db.flush()
    logger.info("custom pack created org=%s pack=%s rules=%d", org_id, pack.id, len(pack.rules))
    return row, True


async def list_packs(db: AsyncSession, *, org_id: str) -> list[OrgCustomPackRow]:
    result = await db.execute(
        select(OrgCustomPackRow)
        .where(OrgCustomPackRow.org_id == org_id)
        .order_by(OrgCustomPackRow.name)
    )
    return list(result.scalars().all())


async def get_pack(db: AsyncSession, *, org_id: str, row_id: str) -> OrgCustomPackRow | None:
    row = await db.get(OrgCustomPackRow, row_id)
    if row is None or row.org_id != org_id:
        return None
    return row


async def delete_pack(db: AsyncSession, *, org_id: str, row_id: str) -> bool:
    row = await get_pack(db, org_id=org_id, row_id=row_id)
    if row is None:
        return False
    await db.delete(row)
    await db.flush()
    logger.info("custom pack deleted org=%s pack=%s", org_id, row.pack_id)
    return True


def load_row_pack(row: OrgCustomPackRow):
    """Re-load a stored bundle into a HuntPack (the sweep's read path).

    Raises :class:`InvalidPackBundle` if a stored row no longer loads (e.g.
    an engine upgrade tightened validation) — the sweep records that as a
    failed run for THIS pack rather than aborting the org's sweep.
    """
    return _load_bundle(row.manifest_yaml, dict(row.rule_files or {}))
