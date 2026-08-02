#!/usr/bin/env python3
"""Idempotently create or reset an admin user's password (B5, #139).

Unlike ``seed-data.py`` this does **not** seed sample data — it is the
production-safe path for bootstrapping the first admin or recovering access
after a prod seed.

> **Prefer ``bt create-admin``.** This script needs the repository *and* a host
> virtualenv that can import ``btagent_backend``; it is not copied into the
> backend image, so it cannot bootstrap a container-only or air-gapped install.
> ``bt create-admin`` ships inside the image and is the documented bootstrap
> path (``docker compose exec backend bt create-admin``). This script is kept
> for host/dev workflows and for ``make db-reset-admin``, and it delegates to
> the same :func:`btagent_backend.cli.admin.create_or_reset_admin` so the two
> can never diverge.

Password source (in priority order):
  1. ``--password`` CLI argument, if given.
  2. ``BTAGENT_SEED_ADMIN_PASSWORD`` environment variable.
In test mode (``BTAGENT_ENV=test``) the password defaults to the username,
matching ``seed-data.py`` so CI behaviour is unchanged. In non-test mode, if
neither source supplies a password the script fails loudly rather than
minting an unrecoverable one.

Behaviour:
  * If the target user exists → its password (and role, for admins) is reset.
  * If the target user does not exist → it is created.

Usage:
    python infra/scripts/reset-admin-password.py [--username admin] [--password PW]
    BTAGENT_SEED_ADMIN_PASSWORD=... python infra/scripts/reset-admin-password.py
"""

import argparse
import asyncio
import os
import sys

# Add project root to path (mirror seed-data.py)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

from btagent_backend.db.engine import async_session_factory
from btagent_backend.auth.bootstrap import (
    SeedPasswordError,
    is_test_mode,
    resolve_admin_password,
)
from btagent_backend.cli.admin import create_or_reset_admin


async def reset_admin_password(
    username: str, password: str, *, role: str = "admin"
) -> None:
    """Create the admin user if missing, otherwise reset its password.

    Idempotent: running it repeatedly converges on a user with the given
    password and role. The create-or-reset logic itself lives in
    ``btagent_backend.cli.admin`` so this script and ``bt create-admin``
    are the same code path.
    """
    async with async_session_factory() as session:
        action = await create_or_reset_admin(
            session, username=username, password=password, role=role
        )
        await session.commit()

    print(
        f"Admin user '{username}' {action} (role={role}). Password applied successfully."
    )
    if not is_test_mode():
        print("Password was NOT printed. Store the value you supplied securely.")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Idempotently create or reset an admin user's password.",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Username to create/reset (default: admin).",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password to set. Falls back to BTAGENT_SEED_ADMIN_PASSWORD.",
    )
    parser.add_argument(
        "--role",
        default="admin",
        help="Role to assign when creating the user (default: admin).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        # An explicit --password always wins; otherwise resolve from env /
        # test-mode rules (and fail loudly in prod when nothing is set).
        if args.password is not None:
            password = args.password
        else:
            password = resolve_admin_password(username=args.username)
        asyncio.run(reset_admin_password(args.username, password, role=args.role))
    except SeedPasswordError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
