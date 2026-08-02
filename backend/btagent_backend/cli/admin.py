"""``bt create-admin`` — bootstrap (or recover) the first admin account.

Why this lives in the ``bt`` CLI and not only in ``infra/scripts``:
``infra/scripts/reset-admin-password.py`` needs the *repository* and a host
virtualenv that can import ``btagent_backend``. It is not copied into the
backend image, so in a container-only or air-gapped install — where there is
no checkout and no venv — there was no way to create the first admin at all.
``bt`` is a console script installed *inside* the image
(``bt = btagent_backend.cli.main:main``), so::

    docker compose exec -e BTAGENT_SEED_ADMIN_PASSWORD=... backend bt create-admin

works with nothing but the image. This is THE bootstrap path; the host script
now delegates to :func:`create_or_reset_admin` here so there is exactly one
implementation of the create-or-reset rule.

Password resolution is *not* re-implemented: it comes from
:func:`btagent_backend.auth.bootstrap.resolve_admin_password` — deterministic
in test mode, ``BTAGENT_SEED_ADMIN_PASSWORD`` otherwise, and a loud failure
when that is unset in a non-test environment (SEC-002). The password is never
echoed back, not even in ``--json`` output.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.bootstrap import (
    ADMIN_PASSWORD_ENV,
    SeedPasswordError,
    is_test_mode,
    resolve_admin_password,
)
from btagent_backend.cli.huntpack import CommandResult


async def create_or_reset_admin(
    db: AsyncSession,
    *,
    username: str = "admin",
    password: str,
    role: str = "admin",
) -> str:
    """Create the user if missing, otherwise reset its password. Idempotent.

    Does **not** commit — the caller owns the transaction (the CLI commits in
    :func:`btagent_backend.cli.main._run`; the host script commits its own
    session). Returns ``"created"`` or ``"reset"``.
    """
    # Imported lazily: hashing pulls bcrypt, which the ``--help`` path and the
    # storage-only commands have no reason to load.
    from btagent_shared.utils.ids import generate_id

    from btagent_backend.auth.jwt import hash_password
    from btagent_backend.db.models import UserRow

    existing = await db.execute(select(UserRow).where(UserRow.username == username))
    user = existing.scalar_one_or_none()

    if user is None:
        db.add(
            UserRow(
                id=generate_id("usr"),
                username=username,
                email=f"{username}@btagent.local",
                password_hash=hash_password(password),
                role=role,
            )
        )
        return "created"

    user.password_hash = hash_password(password)
    # An existing account keeps whatever role it already has: silently
    # promoting some analyst to admin because an operator typo'd a username
    # would be a privilege-escalation footgun.
    return "reset"


async def cmd_create_admin(
    db: AsyncSession,
    *,
    username: str = "admin",
    password: str | None = None,
    role: str = "admin",
) -> CommandResult:
    """``bt create-admin`` — resolve the password, then create-or-reset."""
    try:
        resolved = password if password is not None else resolve_admin_password(username=username)
    except SeedPasswordError as exc:
        return CommandResult(exit_code=1, lines=[str(exc)])

    action = await create_or_reset_admin(db, username=username, password=resolved, role=role)

    lines = [f"admin user '{username}' {action} (role={role} applied on create)."]
    if is_test_mode():
        lines.append(f"test mode: password equals the username ('{username}').")
    else:
        source = "--password" if password is not None else ADMIN_PASSWORD_ENV
        lines.append(
            f"password taken from {source} and NOT printed. Store it in your secret manager."
        )
    lines.append("log in at POST /api/v1/auth/login with that password.")

    return CommandResult(
        exit_code=0,
        lines=lines,
        # Deliberately no password field — this payload is designed to be safe
        # to pipe into a log.
        data={"username": username, "action": action, "role": role},
    )
