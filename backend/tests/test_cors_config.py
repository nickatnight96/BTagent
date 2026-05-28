"""Tests for the prod CORS allowlist enforcement (B7, #141).

Hardened CORS is the default for ``prod``: constructing ``Settings`` with
``BTAGENT_ENV=prod`` must FAIL LOUDLY unless an explicit, non-wildcard,
non-localhost ``cors_origins`` allowlist is supplied. Dev/test stay
permissive so CI (``BTAGENT_ENV=test``) and local dev keep working.

These tests construct ``Settings`` directly (bypassing the ``lru_cache``d
``get_settings`` singleton) so each case is isolated. A strong JWT secret and
non-default S3 key are supplied so only the CORS validator can fire — the
other prod validators stay green.
"""

from __future__ import annotations

import pytest

from btagent_backend.config import Settings

# A 32+ char secret + non-default S3 key so the JWT / S3 prod validators
# pass and only the CORS validator can raise.
_STRONG_JWT = "a" * 64
_REAL_S3_KEY = "real-prod-access-key"


def _prod_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "env": "prod",
        "jwt_secret": _STRONG_JWT,
        "s3_access_key": _REAL_S3_KEY,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_prod_rejects_wildcard_cors() -> None:
    """``*`` in the allowlist is fatal in prod."""
    with pytest.raises(ValueError, match="BTAGENT_CORS_ORIGINS"):
        _prod_settings(cors_origins=["*"])


def test_prod_rejects_empty_cors() -> None:
    """An empty allowlist is fatal in prod (operator never configured it)."""
    with pytest.raises(ValueError, match="BTAGENT_CORS_ORIGINS"):
        _prod_settings(cors_origins=[])


def test_prod_rejects_localhost_default_cors() -> None:
    """Leaving the dev localhost defaults is fatal in prod."""
    with pytest.raises(ValueError, match="localhost"):
        _prod_settings(
            cors_origins=[
                "http://localhost:5173",
                "http://localhost:3000",
            ]
        )


def test_prod_rejects_loopback_ip_cors() -> None:
    """A 127.0.0.1 loopback origin is treated like localhost in prod."""
    with pytest.raises(ValueError, match="localhost"):
        _prod_settings(cors_origins=["http://127.0.0.1:3000"])


def test_prod_accepts_explicit_https_allowlist() -> None:
    """An explicit real-origin allowlist is accepted in prod."""
    settings = _prod_settings(cors_origins=["https://btagent.example.com"])
    assert settings.cors_origins == ["https://btagent.example.com"]


def test_test_env_keeps_localhost_defaults() -> None:
    """``test`` env stays permissive — localhost defaults must NOT raise."""
    settings = Settings(env="test")
    assert "http://localhost:5173" in settings.cors_origins


def test_dev_env_keeps_localhost_defaults() -> None:
    """``dev`` env stays permissive — localhost defaults must NOT raise."""
    settings = Settings(env="dev")
    assert "http://localhost:5173" in settings.cors_origins
