"""``bt`` console-script entrypoint (#112).

Argument parsing, dispatch and session lifecycle for the operator CLI. The
split is deliberate:

* :func:`build_parser` — pure argparse tree, no imports of anything heavy.
* :func:`dispatch` — ``(args, db) -> CommandResult``: takes an **already open**
  session, so tests drive the exact code path the binary runs against the
  shared test database instead of a stubbed one.
* :func:`main` — the only place that opens a session, commits, renders and
  returns an exit code.

argparse rather than click/typer: the CLI must not add a runtime dependency to
the backend image for four subcommands.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from typing import Any

from btagent_backend.cli import huntpack

_EPILOG = """\
examples:
  bt huntpack list
  bt huntpack install ~/sigma --name "SigmaHQ core" --version 2026.07
  bt huntpack enable sigmahq_core
  bt huntpack disable windows_baseline --org org_01HZY...

The target org resolves as: --org, then $BTAGENT_ORG_ID, then the default org.
Every command prints which org it acted on.
"""


def build_parser() -> argparse.ArgumentParser:
    """The full ``bt`` argument tree."""
    parser = argparse.ArgumentParser(
        prog="bt",
        description="BTagent operator CLI.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="group", required=True)

    hp = sub.add_parser("huntpack", help="hunt-pack catalog: list / install / enable / disable")
    hp.add_argument("--org", default=None, help="target organization id (default: $BTAGENT_ORG_ID)")
    hp_sub = hp.add_subparsers(dest="command", required=True)

    hp_sub.add_parser("list", help="list the hunt packs this org can run")

    install = hp_sub.add_parser(
        "install",
        help="install an external Sigma rule directory (SigmaHQ layout) as a hunt pack",
        description=(
            "Parse every rule under PATH, record which ones transpile per backend, skip "
            "unparseable/untranspilable/duplicate rules with a reason, and install the rest "
            "as a hunt pack for this org. Reads a local directory only — nothing is downloaded."
        ),
    )
    install.add_argument("path", help="directory holding the Sigma rules (SigmaHQ layout or flat)")
    install.add_argument("--pack-id", default=None, help="install key (default: slug of --name)")
    install.add_argument("--name", default=None, help="display name (default: directory name)")
    install.add_argument("--version", default="1.0.0", help="pack version (default: 1.0.0)")
    install.add_argument("--description", default="", help="pack description")
    install.add_argument(
        "--backend",
        action="append",
        dest="backends",
        default=None,
        help="backend to check transpile against (repeatable; default: all four)",
    )
    install.add_argument(
        "--skip-transpile-check",
        action="store_true",
        help="import parse-only: do not transpile, do not drop untranspilable rules",
    )
    install.add_argument(
        "--max-rules", type=int, default=None, help="cap the number of rule files imported"
    )
    install.add_argument(
        "--no-enable", action="store_true", help="install without enabling the pack"
    )
    install.add_argument(
        "--overwrite", action="store_true", help="replace an already-installed pack of the same id"
    )
    install.add_argument("--actor", default=None, help="value recorded as updated_by")

    for verb in ("enable", "disable"):
        cmd = hp_sub.add_parser(verb, help=f"{verb} one hunt pack for this org")
        cmd.add_argument("pack_id", help="install key, e.g. windows_baseline")
        cmd.add_argument("--actor", default=None, help="value recorded as updated_by")

    return parser


async def dispatch(args: argparse.Namespace, db: Any) -> huntpack.CommandResult:
    """Run one parsed command against an open session."""
    if args.group != "huntpack":  # pragma: no cover - argparse rejects earlier
        return huntpack.CommandResult(exit_code=2, lines=[f"unknown command group: {args.group}"])

    org_id, org_source = huntpack.resolve_org(getattr(args, "org", None))

    if args.command == "list":
        return await huntpack.cmd_list(db, org_id=org_id, org_source=org_source)
    if args.command == "install":
        return await huntpack.cmd_install(
            db,
            org_id=org_id,
            org_source=org_source,
            path=args.path,
            pack_id=args.pack_id,
            name=args.name,
            version=args.version,
            description=args.description,
            backends=args.backends,
            check_transpile=not args.skip_transpile_check,
            max_rules=args.max_rules,
            enable=not args.no_enable,
            overwrite=args.overwrite,
            actor=args.actor,
        )
    if args.command in ("enable", "disable"):
        return await huntpack.cmd_set_enabled(
            db,
            org_id=org_id,
            org_source=org_source,
            pack_id=args.pack_id,
            enabled=args.command == "enable",
            actor=args.actor,
        )
    return huntpack.CommandResult(exit_code=2, lines=[f"unknown command: {args.command}"])


def render(result: huntpack.CommandResult, *, as_json: bool) -> str:
    """Format a result for stdout."""
    if as_json:
        return json.dumps(
            {"ok": result.ok, "messages": result.lines, "data": result.data},
            indent=2,
            default=str,
        )
    return "\n".join(result.lines)


async def _run(args: argparse.Namespace) -> huntpack.CommandResult:
    """Open a session, run the command, commit on success."""
    # Imported here (not at module import) so ``bt --help`` never builds a DB
    # engine, and so the test suite's engine interception is always in place
    # before the real module would be touched.
    from btagent_backend.db.engine import async_session_factory

    async with async_session_factory() as session:
        try:
            result = await dispatch(args, session)
        except Exception:
            await session.rollback()
            raise
        if result.ok:
            await session.commit()
        else:
            await session.rollback()
        return result


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entrypoint: parse, run, print, return an exit code."""
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        result = asyncio.run(_run(args))
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("aborted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = render(result, as_json=bool(getattr(args, "json", False)))
    print(text, file=sys.stdout if result.ok else sys.stderr)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
