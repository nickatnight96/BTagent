"""``bt create-admin`` / ``bt init-storage`` — the compose bootstrap commands.

These two subcommands exist because a container-only or air-gapped install has
no repository and no virtualenv, so ``infra/scripts/reset-admin-password.py``
cannot run there and nothing ever created the evidence bucket. What the tests
pin down is the behaviour an operator depends on at 03:00:

* create-admin is idempotent and never echoes the password anywhere;
* it refuses to invent an unrecoverable password outside test mode (SEC-002);
* it does not silently promote an existing account's role;
* init-storage needs no database session, so it still works when Postgres is
  down — which is exactly when someone is poking at storage.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from btagent_backend.auth.jwt import verify_password
from btagent_backend.cli import main as cli_main
from btagent_backend.cli import storage as cli_storage
from btagent_backend.db.models import UserRow


async def _dispatch(db, argv):
    args = cli_main.build_parser().parse_args(argv)
    return await cli_main.dispatch(args, db)


async def _get_user(db, username: str) -> UserRow | None:
    result = await db.execute(select(UserRow).where(UserRow.username == username))
    return result.scalar_one_or_none()


# ── argument tree ────────────────────────────────────────────────────────────


def test_parser_exposes_both_bootstrap_commands():
    parser = cli_main.build_parser()

    admin = parser.parse_args(["create-admin"])
    assert admin.group == "create-admin"
    assert admin.username == "admin"
    assert admin.password is None
    assert admin.role == "admin"

    assert parser.parse_args(["init-storage"]).group == "init-storage"


def test_init_storage_declared_as_needing_no_session():
    # The whole point of the group: `bt init-storage` must not build a DB
    # engine, so it stays usable while Postgres is unavailable.
    assert "init-storage" in cli_main._NO_SESSION_GROUPS
    assert "create-admin" not in cli_main._NO_SESSION_GROUPS


# ── create-admin ─────────────────────────────────────────────────────────────


async def test_create_admin_creates_then_resets_idempotently(db_session, sample_org):
    created = await _dispatch(db_session, ["create-admin", "--username", "boot_admin"])
    assert created.exit_code == 0
    assert created.data["action"] == "created"

    user = await _get_user(db_session, "boot_admin")
    assert user is not None
    assert user.role == "admin"
    # Test mode ⇒ deterministic password equal to the username (CI relies on it).
    assert verify_password("boot_admin", user.password_hash)

    again = await _dispatch(db_session, ["create-admin", "--username", "boot_admin"])
    assert again.exit_code == 0
    assert again.data["action"] == "reset"

    # Still exactly one row — "idempotent" means converge, not accumulate.
    rows = (await db_session.execute(select(UserRow).where(UserRow.username == "boot_admin"))).all()
    assert len(rows) == 1


async def test_create_admin_never_echoes_the_password(db_session, sample_org):
    secret = "Sup3r-Secret-Bootstrap-Value"
    result = await _dispatch(
        db_session,
        ["create-admin", "--username", "quiet_admin", "--password", secret],
    )

    assert result.exit_code == 0
    blob = " ".join(result.lines) + repr(result.data)
    assert secret not in blob, "the bootstrap password must never reach stdout or the JSON payload"

    user = await _get_user(db_session, "quiet_admin")
    assert verify_password(secret, user.password_hash)


async def test_create_admin_does_not_promote_an_existing_account(db_session, sample_org):
    """Resetting a *typo'd* username must not hand it the admin role."""
    from btagent_shared.utils.ids import generate_id

    db_session.add(
        UserRow(
            id=generate_id("usr"),
            username="analyst_typo",
            email="analyst_typo@btagent.local",
            password_hash="x",
            role="analyst",
        )
    )
    await db_session.flush()

    result = await _dispatch(
        db_session, ["create-admin", "--username", "analyst_typo", "--password", "pw-reset-value"]
    )

    assert result.exit_code == 0
    assert result.data["action"] == "reset"
    user = await _get_user(db_session, "analyst_typo")
    assert user.role == "analyst", "an existing role must survive a password reset"


async def test_create_admin_fails_loudly_without_a_password_outside_test_mode(
    db_session, sample_org, monkeypatch
):
    monkeypatch.setenv("BTAGENT_ENV", "prod")
    monkeypatch.delenv("BTAGENT_SEED_ADMIN_PASSWORD", raising=False)

    result = await _dispatch(db_session, ["create-admin", "--username", "prod_admin"])

    assert result.exit_code == 1
    assert "BTAGENT_SEED_ADMIN_PASSWORD" in result.lines[0]
    # And it must not have created a half-usable account as a side effect.
    assert await _get_user(db_session, "prod_admin") is None


async def test_create_admin_reads_the_env_var_outside_test_mode(
    db_session, sample_org, monkeypatch
):
    monkeypatch.setenv("BTAGENT_ENV", "prod")
    monkeypatch.setenv("BTAGENT_SEED_ADMIN_PASSWORD", "From-The-Environment-42")

    result = await _dispatch(db_session, ["create-admin", "--username", "env_admin"])

    assert result.exit_code == 0
    user = await _get_user(db_session, "env_admin")
    assert verify_password("From-The-Environment-42", user.password_hash)
    assert "From-The-Environment-42" not in " ".join(result.lines)


# ── init-storage ─────────────────────────────────────────────────────────────


async def test_init_storage_runs_without_a_session(monkeypatch):
    monkeypatch.setattr(cli_storage, "_ensure_bucket_sync", lambda: ("btagent-evidence", "created"))

    result = await _dispatch(None, ["init-storage"])

    assert result.exit_code == 0
    assert result.data == {"bucket": "btagent-evidence", "action": "created"}
    assert "created" in result.lines[0]


async def test_init_storage_is_idempotent(monkeypatch):
    monkeypatch.setattr(cli_storage, "_ensure_bucket_sync", lambda: ("btagent-evidence", "exists"))

    result = await _dispatch(None, ["init-storage"])

    assert result.exit_code == 0
    assert result.data["action"] == "exists"
    assert "already present" in result.lines[0]


async def test_init_storage_reports_a_failure_instead_of_raising(monkeypatch):
    def _boom():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(cli_storage, "_ensure_bucket_sync", _boom)

    result = await _dispatch(None, ["init-storage"])

    assert result.exit_code == 1
    assert "connection refused" in result.lines[0]
    assert "BTAGENT_S3_ENDPOINT" in result.lines[1]
