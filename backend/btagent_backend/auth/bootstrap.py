"""Admin / seed-user password resolution for bootstrap and reset flows.

B5 (#139): centralises the rule for *where* a seed/admin password comes from
so the seed script, the reset CLI, and the unit tests all agree:

* In **test** mode (``BTAGENT_ENV=test``) passwords are deterministic — they
  equal the username — so CI's UAT and E2E jobs can log in. This MUST keep
  working exactly as it did before this change.
* In **non-test** mode the admin password is taken from the
  ``BTAGENT_SEED_ADMIN_PASSWORD`` environment variable. If it is unset we fail
  loudly rather than minting an unrecoverable random password that locks
  operators out (the original SEC-002 bug).

This module is intentionally dependency-free (no DB, no SQLAlchemy) so the
resolution rule can be unit-tested in isolation.
"""

from __future__ import annotations

import os
import secrets

#: Environment variable that supplies the admin password in non-test runs.
ADMIN_PASSWORD_ENV = "BTAGENT_SEED_ADMIN_PASSWORD"


class SeedPasswordError(RuntimeError):
    """Raised when a required seed/admin password cannot be resolved."""


def is_test_mode(env: str | None = None) -> bool:
    """Return True when running in deterministic test mode.

    ``env`` defaults to ``BTAGENT_ENV`` so callers can override it in tests
    without mutating ``os.environ``.
    """
    value = env if env is not None else os.environ.get("BTAGENT_ENV")
    return value == "test"


def resolve_admin_password(
    *,
    username: str = "admin",
    env: str | None = None,
    env_password: str | None | object = ...,
) -> str:
    """Resolve the password to set for the admin user.

    Resolution rules:

    * **test mode** → return ``username`` (deterministic; what CI relies on).
    * **non-test mode** → return ``BTAGENT_SEED_ADMIN_PASSWORD`` when set and
      non-empty; otherwise raise :class:`SeedPasswordError`.

    Args:
        username: the admin username; doubles as the deterministic test password.
        env: explicit ``BTAGENT_ENV`` value (defaults to the real env var).
        env_password: explicit override for the password env var. Left as the
            sentinel ``...`` to mean "read from ``os.environ``"; pass ``None``
            or ``""`` to simulate an unset/empty variable in tests.

    Raises:
        SeedPasswordError: in non-test mode when no password is available.
    """
    if is_test_mode(env):
        return username

    if env_password is ...:
        password = os.environ.get(ADMIN_PASSWORD_ENV)
    else:
        password = env_password  # type: ignore[assignment]

    if password:
        return str(password)

    raise SeedPasswordError(
        f"{ADMIN_PASSWORD_ENV} is not set. Refusing to create or reset the admin "
        "user with an unrecoverable random password in a non-test environment.\n"
        f"Set {ADMIN_PASSWORD_ENV} to a strong password (e.g. "
        f"`export {ADMIN_PASSWORD_ENV}=$(openssl rand -base64 24)`) and re-run, "
        "or use infra/scripts/reset-admin-password.py to (re)set it later."
    )


def resolve_seed_password(
    username: str,
    *,
    env: str | None = None,
) -> str:
    """Resolve the password for a non-admin seed/sample user.

    * **test mode** → deterministic (equals ``username``).
    * **non-test mode** → a random, unrecoverable password. Sample users
      (analyst1 / senior1) are demo fixtures and are never expected to log in
      in production; the recoverable path is reserved for the admin account.
    """
    if is_test_mode(env):
        return username
    return secrets.token_urlsafe(16)
