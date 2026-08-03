"""``bt huntpack …`` — hunt-pack catalog commands (#112).

Four verbs over :mod:`btagent_backend.services.hunt_pack_store`:

* ``list``               — the packs this org can run and which are enabled.
* ``install <path>``     — import an external Sigma corpus (SigmaHQ layout) as
  a hunt pack for this org, skipping unusable rules **with reasons**.
* ``enable`` / ``disable`` — flip one pack's enable state.

Every command function here is pure-ish plumbing: it takes an open
:class:`AsyncSession`, calls the service, and returns a :class:`CommandResult`
(exit code + printable lines + a JSON-able payload). Rendering and session
lifecycle live in :mod:`btagent_backend.cli.main`, which is what lets the tests
drive these against the shared test session directly.

Org scoping
-----------
There is no request and therefore no JWT to derive an org from, so the org is
resolved by :func:`resolve_org` in a fixed order — explicit ``--org``, then
``BTAGENT_ORG_ID``, then :data:`~btagent_backend.db.models.DEFAULT_ORG_ID` —
and **every command prints which org it acted on and where that came from**. A
CLI that silently guessed the tenant would be a quiet way to install one
customer's rules into another's catalog.

The CLI talks to the database directly and is therefore an operator tool with
DB-level trust; it deliberately does **not** re-implement the HTTP API's RBAC
(that gate protects the API's callers, not someone who already holds the
database URL). Writes record ``updated_by="cli:<user>"`` so the audit trail
says a human at a shell did this.
"""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_pack_store

# How many skipped rules a non-JSON install prints in full before summarising.
_SKIP_PREVIEW = 15


@dataclass
class CommandResult:
    """One command's outcome: process exit code + what to print."""

    exit_code: int = 0
    lines: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def resolve_org(explicit: str | None = None) -> tuple[str, str]:
    """Resolve the target org -> ``(org_id, source)``.

    Order: ``--org`` > ``BTAGENT_ORG_ID`` > the default org. ``source`` is the
    human-readable provenance the commands echo back, so an operator always
    knows which tenant they just changed.
    """
    if explicit:
        return explicit, "--org"
    env = os.environ.get("BTAGENT_ORG_ID")
    if env:
        return env, "BTAGENT_ORG_ID"
    return DEFAULT_ORG_ID, "default"


def _actor(explicit: str | None = None) -> str:
    if explicit:
        return explicit[:64]
    try:
        user = getpass.getuser()
    except Exception:  # no passwd entry (containers) — still record the channel
        user = "unknown"
    return f"cli:{user}"[:64]


def _org_banner(org_id: str, source: str) -> str:
    if source == "default":
        return f"org: {org_id} (default — pass --org to target another tenant)"
    return f"org: {org_id} (from {source})"


async def cmd_list(db: AsyncSession, *, org_id: str, org_source: str = "default") -> CommandResult:
    """``bt huntpack list`` — the org's catalog with enable state."""
    catalog = await hunt_pack_store.pack_catalog(db, org_id=org_id)
    lines = [_org_banner(org_id, org_source)]
    if not catalog.items:
        lines.append(
            "no hunt packs available (engine package not installed, or nothing imported yet)"
        )
    else:
        lines.append(f"{'PACK':<32} {'SOURCE':<10} {'VER':<8} {'RULES':>5}  STATE")
        for item in catalog.items:
            state = "enabled" if item.enabled else "disabled"
            if not item.installed:
                state += " (default)" if item.default_enabled else " (not installed)"
            lines.append(
                f"{item.pack_id:<32} {item.source:<10} {item.version:<8} "
                f"{item.rule_count:>5}  {state}"
            )
        lines.append(
            f"{catalog.total} pack(s); defaults: {', '.join(catalog.default_packs) or '-'}"
        )
    return CommandResult(lines=lines, data=catalog.model_dump(mode="json"))


def _max_rules_kwarg(max_rules: int | None) -> dict[str, int | None]:
    """Translate the CLI's ``--max-rules`` into an ``install_corpus_pack`` kwarg.

    Three states, because "not given" and "no cap" are different intents and
    conflating them disarms the control:

    * **omitted** (``None``) — pass nothing, so the service's own E7 default
      cap applies. Previously the CLI forwarded ``max_rules=None`` here, which
      the service reads as *unlimited* — so the primary install path silently
      ran uncapped and the default existed in name only.
    * **0** — the deliberate escape hatch: no cap, import the whole corpus.
    * **N** — cap at N.
    """
    if max_rules is None:
        return {}
    return {"max_rules": None if max_rules == 0 else max_rules}


async def cmd_install(
    db: AsyncSession,
    *,
    org_id: str,
    path: str | Path,
    org_source: str = "default",
    pack_id: str | None = None,
    name: str | None = None,
    version: str = "1.0.0",
    description: str = "",
    backends: list[str] | None = None,
    check_transpile: bool = True,
    max_rules: int | None = None,
    enable: bool = True,
    overwrite: bool = False,
    actor: str | None = None,
) -> CommandResult:
    """``bt huntpack install <path>`` — import an external Sigma corpus."""
    source = Path(path).expanduser()
    if not source.is_dir():
        return CommandResult(exit_code=2, lines=[f"error: not a directory: {source}"])

    # Lazy (the engine is pysigma-heavy and only in the worker/engine image);
    # a bad --backend is a usage error, so it is caught before any work starts.
    from btagent_engine.hunting.transpile import SUPPORTED_BACKENDS

    unknown = [b for b in (backends or []) if b not in SUPPORTED_BACKENDS]
    if unknown:
        return CommandResult(
            exit_code=2,
            lines=[
                f"error: unknown backend(s): {', '.join(unknown)}",
                f"supported backends: {', '.join(SUPPORTED_BACKENDS)}",
            ],
        )

    try:
        result = await hunt_pack_store.install_corpus_pack(
            db,
            org_id=org_id,
            source_dir=source,
            pack_id=pack_id,
            name=name,
            version=version,
            description=description,
            backends=backends,
            check_transpile=check_transpile,
            enable=enable,
            overwrite=overwrite,
            updated_by=_actor(actor),
            **_max_rules_kwarg(max_rules),
        )
    except hunt_pack_store.UnknownPackError as exc:
        return CommandResult(exit_code=2, lines=[f"error: {exc}"])
    except (OSError, ValueError) as exc:
        return CommandResult(exit_code=1, lines=[f"error: install failed: {exc}"])

    lines = [
        _org_banner(org_id, org_source),
        f"installed pack '{result.pack_id}' ({result.name} v{result.version})",
        f"  path:      {result.path}",
        f"  scanned:   {result.scanned} rule file(s)",
        f"  installed: {result.installed}",
        f"  skipped:   {result.skipped_count}",
        f"  enabled:   {'yes' if result.enabled else 'no'}",
    ]
    if result.truncated:
        # E7: ``scanned`` is a POST-cap count, so without this line an install
        # that processed 2000 of 5000 files reports exactly like one that
        # processed a whole 2000-file corpus. Say what was left untouched, and
        # say how to take the cap off.
        not_processed = max(0, result.found - result.scanned)
        lines.insert(
            4,
            f"  CAPPED:    max_rules stopped the import at {result.scanned} of "
            f"{result.found} file(s) found — {not_processed} never processed "
            f"(re-run with --max-rules 0 to import all)",
        )
    if result.coverage:
        lines.append("  transpile coverage (of parsed rules):")
        for backend in sorted(result.coverage):
            cov = result.coverage[backend]
            lines.append(
                f"    {backend:<12} {int(cov['ok']):>4}/{int(cov['total']):<4} "
                f"{cov['rate'] * 100:5.1f}%"
            )
    if result.skipped:
        lines.append("  skipped rules:")
        for skip in result.skipped[:_SKIP_PREVIEW]:
            lines.append(f"    [{skip['stage']}] {skip['file']}: {skip['reason']}")
        remaining = result.skipped_count - _SKIP_PREVIEW
        if remaining > 0:
            lines.append(f"    … and {remaining} more (see install_report.json in the pack dir)")
    return CommandResult(lines=lines, data=result.model_dump(mode="json"))


async def cmd_set_enabled(
    db: AsyncSession,
    *,
    org_id: str,
    pack_id: str,
    enabled: bool,
    org_source: str = "default",
    actor: str | None = None,
) -> CommandResult:
    """``bt huntpack enable|disable <pack-id>``."""
    try:
        row = await hunt_pack_store.set_pack_enabled(
            db,
            org_id=org_id,
            pack_id=pack_id,
            enabled=enabled,
            updated_by=_actor(actor),
        )
    except hunt_pack_store.UnknownPackError as exc:
        known = ", ".join(hunt_pack_store.known_pack_names(org_id)) or "(none)"
        return CommandResult(exit_code=2, lines=[f"error: {exc}", f"known packs: {known}"])

    verb = "enabled" if enabled else "disabled"
    return CommandResult(
        lines=[_org_banner(org_id, org_source), f"{verb} hunt pack '{pack_id}'"],
        data={"pack_id": row.pack_id, "org_id": row.org_id, "enabled": bool(row.enabled)},
    )


__all__ = ["CommandResult", "cmd_install", "cmd_list", "cmd_set_enabled", "resolve_org"]
