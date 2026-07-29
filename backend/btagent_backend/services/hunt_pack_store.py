"""Per-org hunt-pack install/enable store (#112).

The scheduled runner used to run a hardcoded default
(``DEFAULT_BUILTIN_PACKS = ("windows_baseline",)``), so only a handful of the
shipped builtin rules ever ran on a schedule and an org had no way to turn a
pack on or off. This module owns that decision instead:

* :func:`list_builtin_packs` — the catalog of packs shipped in the engine
  image (``btagent_engine/hunting/packs/<name>/pack.yaml``), loaded lazily and
  memoised (the engine import is heavy and only present in the worker image).
* :func:`enabled_pack_names` — **the runner's question**: which packs should
  a scheduled sweep run for this org?
* :func:`set_pack_enabled` — the RBAC-gated write behind the API switch.
* :func:`pack_catalog` — catalog ⋈ org rows, the read behind ``GET /hunt/packs``
  and the HuntPacks screen's enable/disable control.

Resolution semantics (documented because "absence" is meaningful):

* An org with **no rows at all** falls back to :data:`DEFAULT_BUILTIN_PACKS`.
  Behaviour for every existing org is therefore unchanged by this store.
* Once an org has rows, the builtin default set is still treated as
  installed-and-enabled **unless a row explicitly disables it**. Enabling one
  extra pack must not silently switch the baseline pack off — a pack only
  stops running when someone says so.
* Names that are not in the shipped catalog are dropped (with a warning) from
  the runner's list: a pack removed from a later image must not break the
  sweep. Writes reject unknown names outright (:class:`UnknownPackError`).

Org-scoped at every query; flushes but never commits (the route/job wrapper
owns the transaction), matching the rest of the hunt services.
"""

from __future__ import annotations

import logging
from datetime import datetime
from functools import lru_cache

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import OrgHuntPackRow

logger = logging.getLogger("btagent.services.hunt_pack_store")

# The packs a scheduled sweep runs for an org that has never touched the store.
# Kept identical to the pre-store hardcoded default so existing orgs see no
# behaviour change; ``hunt_pack_run_service`` re-exports it under its old name.
DEFAULT_BUILTIN_PACKS: tuple[str, ...] = ("windows_baseline",)


class UnknownPackError(ValueError):
    """A pack name that is not shipped in this image."""


class BuiltinPack(BaseModel):
    """One pack shipped in the engine image (catalog metadata only)."""

    # Install key: the directory name ``load_builtin_pack`` takes.
    pack_id: str
    # The manifest id ``hunt_pack_runs.pack_id`` records for this pack's runs,
    # so the UI can correlate a catalog entry with its run history.
    manifest_pack_id: str
    name: str
    version: str
    description: str = ""
    rule_count: int = 0


class HuntPackCatalogEntry(BuiltinPack):
    """A builtin pack plus this org's install/enable state."""

    enabled: bool
    # True when an explicit org row exists (vs. resolved from the default set).
    installed: bool = False
    # True when the pack is part of :data:`DEFAULT_BUILTIN_PACKS`.
    default_enabled: bool = False
    installed_at: datetime | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None


class HuntPackCatalogResponse(BaseModel):
    items: list[HuntPackCatalogEntry] = Field(default_factory=list)
    total: int = 0
    # The fallback set applied when an org has no rows (surfaced so the UI can
    # explain why a pack reads as enabled without an explicit install).
    default_packs: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Builtin catalog (engine-side, no DB)
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def list_builtin_packs() -> tuple[BuiltinPack, ...]:
    """Metadata for every pack shipped under ``btagent_engine/hunting/packs``.

    Memoised: the pack set is immutable for the life of the process (it ships
    in the image). Returns ``()`` when the engine is not installed (the
    backend-only image) — callers must treat an empty catalog as "unknown",
    not as "no packs enabled".
    """
    try:
        # Lazy: the engine package is only present in the worker/engine image.
        from btagent_engine.hunting.pack import BUILTIN_PACKS_DIR, PackLoadError, load_pack
    except Exception:  # pragma: no cover - depends on the deployed image
        logger.info("hunt pack catalog unavailable: btagent_engine not installed")
        return ()

    packs: list[BuiltinPack] = []
    for pack_dir in sorted(p for p in BUILTIN_PACKS_DIR.iterdir() if p.is_dir()):
        if not (pack_dir / "pack.yaml").is_file():
            continue
        try:
            pack = load_pack(pack_dir)
        except PackLoadError:
            logger.warning("skipping malformed builtin pack: %s", pack_dir.name, exc_info=True)
            continue
        packs.append(
            BuiltinPack(
                pack_id=pack_dir.name,
                manifest_pack_id=pack.id,
                name=pack.name,
                version=pack.version,
                description=pack.description,
                rule_count=len(pack.enabled_rules),
            )
        )
    return tuple(packs)


def builtin_pack_names() -> tuple[str, ...]:
    """Install keys of every shipped pack (``()`` when the engine is absent)."""
    return tuple(p.pack_id for p in list_builtin_packs())


# --------------------------------------------------------------------------- #
# Org rows
# --------------------------------------------------------------------------- #


async def list_org_packs(db: AsyncSession, *, org_id: str) -> list[OrgHuntPackRow]:
    """Every explicit pack row for one org, ordered by install key."""
    result = await db.execute(
        select(OrgHuntPackRow)
        .where(OrgHuntPackRow.org_id == org_id)
        .order_by(OrgHuntPackRow.pack_id)
    )
    return list(result.scalars().all())


def resolve_enabled(explicit: dict[str, bool], *, known: tuple[str, ...] = ()) -> list[str]:
    """Pure resolution of an org's enabled pack set (see module docstring).

    ``explicit`` maps pack name → enabled from the org's rows. ``known`` is the
    shipped catalog; when it is empty (engine not installed) no filtering is
    applied, because an empty catalog means "unknown", not "nothing exists".
    """
    if not explicit:
        resolved = set(DEFAULT_BUILTIN_PACKS)
    else:
        resolved = {name for name in DEFAULT_BUILTIN_PACKS if explicit.get(name, True)}
        resolved |= {name for name, enabled in explicit.items() if enabled}
    if known:
        unknown = sorted(resolved - set(known))
        if unknown:
            logger.warning("ignoring hunt packs not shipped in this image: %s", unknown)
        resolved &= set(known)
    return sorted(resolved)


async def enabled_pack_names(db: AsyncSession, *, org_id: str) -> list[str]:
    """The packs a scheduled sweep should run for ``org_id``.

    Falls back to :data:`DEFAULT_BUILTIN_PACKS` when the org has no rows, so an
    org that never touched the store behaves exactly as it did before the store
    existed. Read-only.
    """
    rows = await list_org_packs(db, org_id=org_id)
    return resolve_enabled({r.pack_id: bool(r.enabled) for r in rows}, known=builtin_pack_names())


async def set_pack_enabled(
    db: AsyncSession,
    *,
    org_id: str,
    pack_id: str,
    enabled: bool,
    updated_by: str | None = None,
) -> OrgHuntPackRow:
    """Install (on first write) and set one pack's enable state for an org.

    Raises :class:`UnknownPackError` for a name the image does not ship — the
    store must never persist a pack the runner cannot load. Flushes but never
    commits.
    """
    known = builtin_pack_names()
    if known and pack_id not in known:
        raise UnknownPackError(f"unknown hunt pack: {pack_id!r}")

    row = await db.get(OrgHuntPackRow, (org_id, pack_id))
    if row is None:
        row = OrgHuntPackRow(
            org_id=org_id,
            pack_id=pack_id,
            enabled=enabled,
            updated_by=updated_by,
        )
        db.add(row)
    else:
        row.enabled = enabled
        row.updated_by = updated_by
    await db.flush()
    logger.info(
        "hunt pack %s for org=%s: pack=%s by=%s",
        "enabled" if enabled else "disabled",
        org_id,
        pack_id,
        updated_by,
    )
    return row


def _entry(
    pack: BuiltinPack, row: OrgHuntPackRow | None, *, enabled_set: set[str]
) -> HuntPackCatalogEntry:
    return HuntPackCatalogEntry(
        **pack.model_dump(),
        enabled=pack.pack_id in enabled_set,
        installed=row is not None,
        default_enabled=pack.pack_id in DEFAULT_BUILTIN_PACKS,
        installed_at=row.installed_at if row is not None else None,
        updated_at=row.updated_at if row is not None else None,
        updated_by=row.updated_by if row is not None else None,
    )


async def pack_catalog(db: AsyncSession, *, org_id: str) -> HuntPackCatalogResponse:
    """The shipped catalog joined with this org's install/enable state."""
    rows = {r.pack_id: r for r in await list_org_packs(db, org_id=org_id)}
    packs = list_builtin_packs()
    enabled_set = set(
        resolve_enabled(
            {name: bool(r.enabled) for name, r in rows.items()},
            known=tuple(p.pack_id for p in packs),
        )
    )
    return HuntPackCatalogResponse(
        items=[_entry(p, rows.get(p.pack_id), enabled_set=enabled_set) for p in packs],
        total=len(packs),
        default_packs=list(DEFAULT_BUILTIN_PACKS),
    )


__all__ = [
    "DEFAULT_BUILTIN_PACKS",
    "BuiltinPack",
    "HuntPackCatalogEntry",
    "HuntPackCatalogResponse",
    "UnknownPackError",
    "builtin_pack_names",
    "enabled_pack_names",
    "list_builtin_packs",
    "list_org_packs",
    "pack_catalog",
    "resolve_enabled",
    "set_pack_enabled",
]
