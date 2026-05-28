"""Unit tests for admin/seed password resolution (B5, #139).

These exercise :mod:`btagent_backend.auth.bootstrap` in isolation — no DB, no
SQLAlchemy — so the production-vs-test resolution rules are pinned
independently of the seed script and the reset CLI.
"""

import pytest

from btagent_backend.auth.bootstrap import (
    ADMIN_PASSWORD_ENV,
    SeedPasswordError,
    is_test_mode,
    resolve_admin_password,
    resolve_seed_password,
)

# ── is_test_mode ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ("test", True),
        ("dev", False),
        ("prod", False),
        ("staging", False),
        ("", False),
    ],
)
def test_is_test_mode_explicit_value(env, expected):
    """An explicit (non-None) ``env`` value is decided without reading os.environ."""
    assert is_test_mode(env) is expected


def test_is_test_mode_none_reads_os_environ(monkeypatch):
    """``env=None`` falls back to BTAGENT_ENV (this is the production code path)."""
    monkeypatch.setenv("BTAGENT_ENV", "test")
    assert is_test_mode(None) is True
    monkeypatch.setenv("BTAGENT_ENV", "prod")
    assert is_test_mode(None) is False
    monkeypatch.delenv("BTAGENT_ENV", raising=False)
    assert is_test_mode(None) is False


# ── resolve_admin_password ───────────────────────────────────────────────────


def test_admin_password_test_mode_is_deterministic():
    """Test mode returns username==password so CI UAT/E2E can log in."""
    assert resolve_admin_password(username="admin", env="test", env_password=None) == "admin"


def test_admin_password_test_mode_ignores_env_password():
    """Even if the env var is set, test mode stays deterministic."""
    assert resolve_admin_password(username="admin", env="test", env_password="ignored") == "admin"


def test_admin_password_prod_uses_env_value():
    assert (
        resolve_admin_password(username="admin", env="prod", env_password="s3cret-pw")
        == "s3cret-pw"
    )


@pytest.mark.parametrize("env", ["prod", "staging", "dev"])
def test_admin_password_non_test_uses_env_value(env):
    assert resolve_admin_password(username="admin", env=env, env_password="from-env") == "from-env"


@pytest.mark.parametrize("missing", [None, ""])
def test_admin_password_prod_unset_fails_loudly(missing):
    with pytest.raises(SeedPasswordError) as exc:
        resolve_admin_password(username="admin", env="prod", env_password=missing)
    # Error message must name the env var so operators know what to set.
    assert ADMIN_PASSWORD_ENV in str(exc.value)


def test_admin_password_reads_from_os_environ_when_set(monkeypatch):
    monkeypatch.setenv("BTAGENT_ENV", "prod")
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, "env-driven-pw")
    assert resolve_admin_password(username="admin") == "env-driven-pw"


def test_admin_password_os_environ_unset_in_prod_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_ENV", "prod")
    monkeypatch.delenv(ADMIN_PASSWORD_ENV, raising=False)
    with pytest.raises(SeedPasswordError):
        resolve_admin_password(username="admin")


def test_admin_password_os_environ_test_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_ENV", "test")
    monkeypatch.delenv(ADMIN_PASSWORD_ENV, raising=False)
    assert resolve_admin_password(username="admin") == "admin"


# ── resolve_seed_password (non-admin sample users) ───────────────────────────


def test_seed_password_test_mode_is_deterministic():
    assert resolve_seed_password("analyst1", env="test") == "analyst1"


def test_seed_password_non_test_is_random_and_nonempty():
    pw1 = resolve_seed_password("analyst1", env="prod")
    pw2 = resolve_seed_password("analyst1", env="prod")
    assert pw1 and pw2
    # Random per call — astronomically unlikely to collide.
    assert pw1 != pw2
