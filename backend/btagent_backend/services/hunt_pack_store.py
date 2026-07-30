"""Per-org hunt-pack install/enable store (#112).

The scheduled runner used to run a hardcoded default
(``DEFAULT_BUILTIN_PACKS = ("windows_baseline",)``), so only a handful of the
shipped builtin rules ever ran on a schedule and an org had no way to turn a
pack on or off. This module owns that decision instead:

* :func:`list_builtin_packs` — the catalog of packs shipped in the engine
  image (``btagent_engine/hunting/packs/<name>/pack.yaml``), loaded lazily and
  memoised (the engine import is heavy and only present in the worker image).
* :func:`list_installed_packs` — **externally imported** packs for one org
  (#112 corpus install): a SigmaHQ-layout rule tree turned into a normal pack
  directory under ``<hunt_pack_install_dir>/<org_id>/<pack_id>/``. Cached on a
  directory fingerprint rather than memoised for the process lifetime (unlike
  the builtin catalog) because an operator can install a pack at any time.
* :func:`enabled_pack_names` — **the runner's question**: which packs should
  a scheduled sweep run for this org?
* :func:`set_pack_enabled` — the RBAC-gated write behind the API switch.
* :func:`pack_catalog` — catalog ⋈ org rows, the read behind ``GET /hunt/packs``
  and the HuntPacks screen's enable/disable control.
* :func:`install_corpus_pack` — the #112 install path: import an external
  Sigma corpus (skipping unusable rules with reasons), materialise it as a
  pack directory for **this org only**, and record the enable row.
* :func:`load_pack_for_org` — the loader the runner uses: an org's installed
  packs first, then the builtin catalog.

Resolution semantics (documented because "absence" is meaningful):

* An org with **no rows at all** falls back to :data:`DEFAULT_BUILTIN_PACKS`.
  Behaviour for every existing org is therefore unchanged by this store.
* Once an org has rows, the builtin default set is still treated as
  installed-and-enabled **unless a row explicitly disables it**. Enabling one
  extra pack must not silently switch the baseline pack off — a pack only
  stops running when someone says so.
* Names that are not in the *known* catalog (shipped **or** installed for this
  org) are dropped (with a warning) from the runner's list: a pack removed
  from a later image must not break the sweep. Writes reject unknown names
  outright (:class:`UnknownPackError`).

Org-scoped at every query; flushes but never commits (the route/job wrapper
owns the transaction), matching the rest of the hunt services. Installed packs
are org-scoped **on disk too** (one directory per org under the install root)
— an imported corpus is that tenant's data, so it must not surface in another
tenant's catalog.

No new table (#112 install round): the imported pack's rules live on disk as a
normal pack directory and its enable state reuses ``org_hunt_packs`` exactly
as a builtin pack does.
"""

from __future__ import annotations

import logging
import re
import shutil
from collections.abc import Sequence
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import get_settings
from btagent_backend.db.models_hunt import OrgHuntPackRow

if TYPE_CHECKING:  # avoid importing the (pysigma-heavy) engine at module load
    from btagent_engine.hunting.corpus import CorpusImport
    from btagent_engine.hunting.pack import HuntPack

logger = logging.getLogger("btagent.services.hunt_pack_store")

# Install keys / org ids allowed to become path segments under the install
# root. Anything outside this alphabet (``..``, ``/``, NUL, …) is rejected
# rather than sanitised — a traversal attempt is a bug, not a typo to fix up.
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# The packs a scheduled sweep runs for an org that has never touched the store.
# Kept identical to the pre-store hardcoded default so existing orgs see no
# behaviour change; ``hunt_pack_run_service`` re-exports it under its old name.
DEFAULT_BUILTIN_PACKS: tuple[str, ...] = ("windows_baseline",)


class UnknownPackError(ValueError):
    """A pack name that is not shipped in this image."""


class BuiltinPack(BaseModel):
    """One pack available to an org (catalog metadata only).

    Named for the original builtin-only catalog; since the #112 corpus-install
    round an entry may equally be an *imported* pack (``source="installed"``),
    which the runner loads and runs identically.
    """

    # Install key: the directory name ``load_builtin_pack`` takes.
    pack_id: str
    # The manifest id ``hunt_pack_runs.pack_id`` records for this pack's runs,
    # so the UI can correlate a catalog entry with its run history.
    manifest_pack_id: str
    name: str
    version: str
    description: str = ""
    rule_count: int = 0
    # "builtin" (shipped in the engine image) or "installed" (imported for
    # this org from an external Sigma corpus).
    source: str = "builtin"


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
# Installed (externally imported) packs — org-scoped directories on disk
# --------------------------------------------------------------------------- #


class InstallResult(BaseModel):
    """What an external-corpus install did, for the CLI / caller to report."""

    pack_id: str
    manifest_pack_id: str
    name: str
    version: str
    org_id: str
    path: str
    enabled: bool
    scanned: int = 0
    installed: int = 0
    skipped: list[dict[str, Any]] = Field(default_factory=list)
    # ``{backend: {"ok": int, "total": int, "rate": float}}`` over parsed rules.
    coverage: dict[str, dict[str, float]] = Field(default_factory=dict)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


def _safe_segment(value: str, *, label: str) -> str:
    """Validate one path segment (org id / pack id) before it touches disk."""
    if not _SAFE_SEGMENT_RE.match(value or ""):
        raise UnknownPackError(f"unsafe {label}: {value!r}")
    return value


def install_root() -> Path:
    """Root directory external packs are materialised under (never created here)."""
    return Path(get_settings().hunt_pack_install_dir).expanduser()


def org_install_dir(org_id: str) -> Path:
    """The install directory owned by one org (org-scoped on disk)."""
    return install_root() / _safe_segment(org_id, label="org id")


def installed_pack_dir(org_id: str, pack_id: str) -> Path:
    """Where one org's installed pack lives."""
    return org_install_dir(org_id) / _safe_segment(pack_id, label="pack id")


def _install_signature(root: Path) -> tuple[tuple[str, int, int], ...]:
    """A cheap fingerprint of one org's install dir (one ``stat`` per pack).

    Changes whenever a pack is added, removed, or re-installed — which is
    exactly when the cached catalog below must be rebuilt.
    """
    entries: list[tuple[str, int, int]] = []
    for pack_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        manifest = pack_dir / "pack.yaml"
        try:
            stat = manifest.stat()
        except OSError:
            continue
        entries.append((pack_dir.name, stat.st_mtime_ns, stat.st_size))
    return tuple(entries)


# install-dir path -> (signature, catalog). Loading a pack parses every rule
# file in it, and an imported corpus can hold a thousand of them, so the
# catalog read behind ``GET /hunt/packs`` (and every scheduler tick) must not
# re-parse on each call. Invalidated by the signature above, so an install or
# re-install is picked up immediately.
_installed_cache: dict[str, tuple[tuple[tuple[str, int, int], ...], tuple[BuiltinPack, ...]]] = {}


def list_installed_packs(org_id: str) -> tuple[BuiltinPack, ...]:
    """Catalog metadata for every pack imported into ``org_id``.

    Read strictly from *this org's* directory (packs appear at operator
    command, not at image build, so the result is cached on a directory
    fingerprint rather than memoised for the process lifetime). A malformed
    pack directory is logged and skipped, never raised — one bad import must
    not blank the catalog. ``()`` when the engine is absent or nothing is
    installed.
    """
    try:
        from btagent_engine.hunting.pack import PackLoadError, load_pack
    except Exception:  # pragma: no cover - depends on the deployed image
        return ()

    try:
        root = org_install_dir(org_id)
    except UnknownPackError:
        logger.warning("refusing to scan installed packs for unsafe org id")
        return ()
    cache_key = str(root)
    if not root.is_dir():
        _installed_cache.pop(cache_key, None)
        return ()

    signature = _install_signature(root)
    cached = _installed_cache.get(cache_key)
    if cached is not None and cached[0] == signature:
        return cached[1]

    packs: list[BuiltinPack] = []
    for pack_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if not (pack_dir / "pack.yaml").is_file():
            continue
        try:
            pack = load_pack(pack_dir)
        except PackLoadError:
            logger.warning("skipping malformed installed pack: %s", pack_dir.name, exc_info=True)
            continue
        packs.append(
            BuiltinPack(
                pack_id=pack_dir.name,
                manifest_pack_id=pack.id,
                name=pack.name,
                version=pack.version,
                description=pack.description,
                rule_count=len(pack.enabled_rules),
                source="installed",
            )
        )
    result = tuple(packs)
    _installed_cache[cache_key] = (signature, result)
    return result


def list_packs(org_id: str) -> tuple[BuiltinPack, ...]:
    """Every pack this org can run: shipped builtins + its imported packs.

    A builtin name always wins — :func:`install_corpus_pack` refuses to shadow
    one — so the two sets are disjoint by construction.
    """
    builtins = list_builtin_packs()
    builtin_names = {p.pack_id for p in builtins}
    installed = tuple(p for p in list_installed_packs(org_id) if p.pack_id not in builtin_names)
    return tuple(builtins) + installed


def known_pack_names(org_id: str) -> tuple[str, ...]:
    """Install keys of every pack ``org_id`` can run (builtin + installed)."""
    return tuple(p.pack_id for p in list_packs(org_id))


def load_pack_for_org(name: str, *, org_id: str) -> HuntPack:
    """Load a pack by install key for one org: installed first, then builtin.

    The loader the scheduled runner uses, so an imported corpus runs through
    exactly the same transpile → execute → ingest pipeline as a shipped pack.
    """
    from btagent_engine.hunting.pack import load_builtin_pack, load_pack

    try:
        candidate = installed_pack_dir(org_id, name)
    except UnknownPackError:
        candidate = None
    if candidate is not None and (candidate / "pack.yaml").is_file():
        return load_pack(candidate)
    return load_builtin_pack(name)


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
    return resolve_enabled(
        {r.pack_id: bool(r.enabled) for r in rows}, known=known_pack_names(org_id)
    )


async def set_pack_enabled(
    db: AsyncSession,
    *,
    org_id: str,
    pack_id: str,
    enabled: bool,
    updated_by: str | None = None,
) -> OrgHuntPackRow:
    """Install (on first write) and set one pack's enable state for an org.

    Raises :class:`UnknownPackError` for a name this org cannot run (neither
    shipped in the image nor installed for the org) — the store must never
    persist a pack the runner cannot load. Flushes but never commits.
    """
    known = known_pack_names(org_id)
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
    """The catalog this org can run (builtin + imported + custom) ⋈ enable state.

    Uploaded bundle packs (``org_custom_packs``, #112 slice 2) run on every
    sweep by existence, so they belong on the same screen as the packs they
    run alongside — as ``source="custom"`` entries that always read enabled.
    They are not toggleable through ``PUT /hunt/packs/{pack_id}`` (that would
    404); their lifecycle is upload/delete in the custom-packs API.
    """
    from btagent_backend.services import org_custom_pack_service

    rows = {r.pack_id: r for r in await list_org_packs(db, org_id=org_id)}
    packs = list_packs(org_id)
    enabled_set = set(
        resolve_enabled(
            {name: bool(r.enabled) for name, r in rows.items()},
            known=tuple(p.pack_id for p in packs),
        )
    )
    items = [_entry(p, rows.get(p.pack_id), enabled_set=enabled_set) for p in packs]

    taken = {e.pack_id for e in items}
    for custom in await org_custom_pack_service.list_packs(db, org_id=org_id):
        if custom.pack_id in taken:  # defence in depth; the upload API refuses these
            continue
        items.append(
            HuntPackCatalogEntry(
                pack_id=custom.pack_id,
                # A bundle row stores the manifest id itself — the id its
                # sweep runs carry — so the two keys coincide.
                manifest_pack_id=custom.pack_id,
                name=custom.name,
                version=custom.version,
                description=custom.description or "",
                rule_count=custom.rule_count,
                source="custom",
                enabled=True,
                installed=True,
                default_enabled=False,
                installed_at=custom.created_at,
                updated_at=custom.updated_at,
                updated_by=custom.created_by,
            )
        )

    return HuntPackCatalogResponse(
        items=items,
        total=len(items),
        default_packs=list(DEFAULT_BUILTIN_PACKS),
    )


# --------------------------------------------------------------------------- #
# External corpus install (#112)
# --------------------------------------------------------------------------- #


def _coverage_payload(imported: CorpusImport) -> dict[str, dict[str, float]]:
    return {
        backend: {"ok": float(cov.ok), "total": float(cov.total), "rate": round(cov.rate, 4)}
        for backend, cov in imported.coverage().items()
    }


async def install_corpus_pack(
    db: AsyncSession,
    *,
    org_id: str,
    source_dir: str | Path,
    pack_id: str | None = None,
    name: str | None = None,
    version: str = "1.0.0",
    description: str = "",
    backends: Sequence[str] | None = None,
    check_transpile: bool = True,
    max_rules: int | None = None,
    enable: bool = True,
    overwrite: bool = False,
    updated_by: str | None = None,
) -> InstallResult:
    """Install an external Sigma corpus (SigmaHQ layout) as this org's hunt pack.

    Reuses the engine's importer end to end: parse every rule, record which
    ones transpile per backend, **skip with a reason** the ones that cannot be
    parsed / transpiled / are duplicates, and materialise the survivors as a
    normal pack directory under this org's install root. The enable state then
    rides the existing ``org_hunt_packs`` row — no new table.

    Raises :class:`UnknownPackError` when the derived install key collides with
    a shipped builtin pack (a builtin must never be shadowed) or is unsafe as a
    path segment. Everything else that goes wrong per-rule is a skip, not an
    error. Flushes but never commits.
    """
    from btagent_engine.hunting.corpus import import_sigma_corpus, slugify, write_pack_dir
    from btagent_engine.hunting.transpile import SUPPORTED_BACKENDS

    source = Path(source_dir).expanduser()
    pack_name = name or source.resolve().name
    key = _safe_segment(pack_id or slugify(pack_name), label="pack id")
    if key in set(builtin_pack_names()):
        raise UnknownPackError(f"{key!r} is a builtin pack name; choose another --pack-id")

    requested_backends = list(backends or SUPPORTED_BACKENDS)
    # Guard here rather than letting an unknown name fail every rule's
    # transpile — that would look like "the whole corpus is unusable".
    unknown_backends = [b for b in requested_backends if b not in set(SUPPORTED_BACKENDS)]
    if unknown_backends:
        raise ValueError(
            f"unknown backend(s): {', '.join(unknown_backends)}; "
            f"supported: {', '.join(SUPPORTED_BACKENDS)}"
        )

    imported = import_sigma_corpus(
        source,
        name=pack_name,
        version=version,
        description=description,
        backends=requested_backends,
        check_transpile=check_transpile,
        max_rules=max_rules,
    )

    dest = installed_pack_dir(org_id, key)
    replaced_existing = dest.exists()
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_pack_dir(imported, dest, overwrite=overwrite)

    row: OrgHuntPackRow | None = None
    try:
        row = await set_pack_enabled(
            db, org_id=org_id, pack_id=key, enabled=enable, updated_by=updated_by
        )
    except Exception:
        # The row is the record of the install; without it a *new* pack
        # directory is orphaned state nobody can reach, so remove it. A
        # re-install (``overwrite``) is left in place: its row already exists,
        # and deleting the directory would take the previous version with it.
        if not replaced_existing:
            shutil.rmtree(dest, ignore_errors=True)
        raise

    logger.info(
        "hunt pack installed from corpus: org=%s pack=%s rules=%d skipped=%d source=%s",
        org_id,
        key,
        imported.installed,
        len(imported.skipped),
        source,
    )
    return InstallResult(
        pack_id=key,
        manifest_pack_id=imported.pack.id,
        name=imported.pack.name,
        version=imported.pack.version,
        org_id=org_id,
        path=str(dest),
        enabled=bool(row.enabled),
        scanned=imported.scanned,
        installed=imported.installed,
        skipped=[s.model_dump() for s in imported.skipped],
        coverage=_coverage_payload(imported),
    )


__all__ = [
    "DEFAULT_BUILTIN_PACKS",
    "BuiltinPack",
    "HuntPackCatalogEntry",
    "HuntPackCatalogResponse",
    "InstallResult",
    "UnknownPackError",
    "builtin_pack_names",
    "enabled_pack_names",
    "install_corpus_pack",
    "install_root",
    "installed_pack_dir",
    "known_pack_names",
    "list_builtin_packs",
    "list_installed_packs",
    "list_org_packs",
    "list_packs",
    "load_pack_for_org",
    "org_install_dir",
    "pack_catalog",
    "resolve_enabled",
    "set_pack_enabled",
]
