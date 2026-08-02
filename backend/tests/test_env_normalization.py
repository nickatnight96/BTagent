"""Regression tests for BTAGENT_ENV normalization (P1.6).

Four independent security gates keyed off ``settings.env == "prod"``:

  1. ``config.Settings._validate_cors_origins`` — the prod CORS allowlist.
  2. ``main.create_app``                        — /api/docs + /api/redoc disable.
  3. ``middleware.security_headers``            — the HSTS response header.
  4. ``auth.middleware._assert_token_not_revoked`` — legacy no-jti rejection.

Every shipped deployment artifact spells the environment ``production``:
``infra/helm/btagent/values.yaml``, ``values-production.yaml``,
``values-airgap.yaml`` and ``infra/.env.airgap.example``. So on a real install
all four gates silently no-opped — nothing raised, nothing logged, and the app
looked healthy while running a dev security posture.

These tests assert the two spellings are INDISTINGUISHABLE at every gate. They
are written per-gate rather than against the normaliser alone, so that a future
gate reintroducing a raw ``env == "prod"`` comparison fails here.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from btagent_backend.config import Settings

# Both spellings of the same environment. Any assertion in this module that
# holds for one must hold identically for the other.
_PROD_SPELLINGS = ("prod", "production")

_STRONG_JWT = "a" * 64
_REAL_S3_KEY = "real-prod-access-key"
_REAL_S3_SECRET = "real-prod-secret-key"
_REAL_ORIGINS = ["https://btagent.example.com"]


def _prod_settings(spelling: str, **overrides: object) -> Settings:
    """A valid prod ``Settings`` written with the given spelling of the env."""
    base: dict[str, object] = {
        "env": spelling,
        "jwt_secret": _STRONG_JWT,
        "s3_access_key": _REAL_S3_KEY,
        "s3_secret_key": _REAL_S3_SECRET,
        "cors_origins": _REAL_ORIGINS,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _patch_settings(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    """Point every ``get_settings`` binding a prod gate reads at ``settings``.

    The gates reach config through three different bindings — ``main`` and
    ``security_headers`` import the function at module load, ``auth.middleware``
    imports it inside the function body — so all three have to be redirected
    for an end-to-end gate assertion.
    """
    import btagent_backend.config as config_mod
    import btagent_backend.main as main_mod
    import btagent_backend.middleware.security_headers as headers_mod

    for module in (config_mod, main_mod, headers_mod):
        monkeypatch.setattr(module, "get_settings", lambda: settings)


# ---------------------------------------------------------------------------
# The normaliser itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
def test_both_spellings_canonicalise_to_prod(spelling: str) -> None:
    settings = _prod_settings(spelling)
    assert settings.env == "prod"
    assert settings.is_production is True


@pytest.mark.parametrize("raw", ["PRODUCTION", "  production  ", "Prod", "PROD"])
def test_casing_and_whitespace_are_normalised(raw: str) -> None:
    """``BTAGENT_ENV=Production`` is the same silent-no-op bug in another dress."""
    assert _prod_settings(raw).env == "prod"


@pytest.mark.parametrize("env", ["dev", "test"])
def test_non_prod_environments_are_not_production(env: str) -> None:
    assert Settings(env=env).is_production is False


def test_staging_is_not_production() -> None:
    """``staging`` runs the non-dev credential validators but not the prod gates."""
    assert _prod_settings("staging").is_production is False


def test_unknown_environment_is_not_treated_as_dev() -> None:
    """An unrecognised value must fail SAFE (strict), never relax the posture.

    ``development`` is deliberately NOT aliased to ``dev``: falling through to
    the strict branch of the ``("dev", "test")`` carve-outs is the safe error.
    """
    with pytest.raises(ValueError, match="known default"):
        Settings(env="development", jwt_secret="CHANGE-ME-IN-PRODUCTION")


# ---------------------------------------------------------------------------
# Gate 1 — prod CORS allowlist enforcement (config.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
def test_gate_cors_rejects_localhost_defaults(spelling: str) -> None:
    with pytest.raises(ValueError, match="localhost"):
        _prod_settings(spelling, cors_origins=["http://localhost:5173"])


@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
def test_gate_cors_rejects_wildcard(spelling: str) -> None:
    with pytest.raises(ValueError, match="BTAGENT_CORS_ORIGINS"):
        _prod_settings(spelling, cors_origins=["*"])


@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
def test_gate_cors_accepts_real_allowlist(spelling: str) -> None:
    assert _prod_settings(spelling).cors_origins == _REAL_ORIGINS


# ---------------------------------------------------------------------------
# Gate 2 — /api/docs + /api/redoc disabled in prod (main.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
def test_gate_docs_disabled_in_prod(spelling: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from btagent_backend.main import create_app

    _patch_settings(monkeypatch, _prod_settings(spelling))
    app = create_app()
    assert app.docs_url is None
    assert app.redoc_url is None


def test_gate_docs_enabled_outside_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: the gate is real, not vacuously passing for every env."""
    from btagent_backend.main import create_app

    _patch_settings(monkeypatch, Settings(env="test"))
    app = create_app()
    assert app.docs_url == "/api/docs"
    assert app.redoc_url == "/api/redoc"


# ---------------------------------------------------------------------------
# Gate 3 — HSTS response header (middleware/security_headers.py)
# ---------------------------------------------------------------------------


async def _hsts_header_for(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> str | None:
    """Return the ``Strict-Transport-Security`` header the app would emit.

    Requests an unrouted path: the middleware runs on every response including
    the 404, which keeps this gate assertion free of DB/lifespan setup.
    """
    from btagent_backend.main import create_app

    _patch_settings(monkeypatch, settings)
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        resp = await ac.get("/__no_such_route__")
    return resp.headers.get("Strict-Transport-Security")


@pytest.mark.asyncio
@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
async def test_gate_hsts_set_in_prod(spelling: str, monkeypatch: pytest.MonkeyPatch) -> None:
    header = await _hsts_header_for(_prod_settings(spelling), monkeypatch)
    assert header == "max-age=31536000; includeSubDomains"


@pytest.mark.asyncio
async def test_gate_hsts_absent_outside_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: HSTS over plain http://localhost would be a permanent trap."""
    assert await _hsts_header_for(Settings(env="test"), monkeypatch) is None


# ---------------------------------------------------------------------------
# Gate 4 — legacy no-jti access tokens rejected in prod (auth/middleware.py)
# ---------------------------------------------------------------------------


def _legacy_payload():
    """An access-token payload with no ``jti`` — i.e. not individually revocable."""
    from datetime import UTC, datetime, timedelta

    from btagent_backend.auth.jwt import TokenPayload

    return TokenPayload(
        sub="usr_legacy_1",
        username="legacy",
        role="analyst",
        exp=datetime.now(UTC) + timedelta(minutes=15),
        type="access",
        jti=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("spelling", _PROD_SPELLINGS)
async def test_gate_legacy_no_jti_rejected_in_prod(
    spelling: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi import HTTPException

    from btagent_backend.auth.middleware import _assert_token_not_revoked

    _patch_settings(monkeypatch, _prod_settings(spelling))
    with pytest.raises(HTTPException) as exc:
        await _assert_token_not_revoked(_legacy_payload())
    assert exc.value.status_code == 401
    assert "jti" in exc.value.detail


@pytest.mark.asyncio
async def test_gate_legacy_no_jti_accepted_outside_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: dev/test still warn-and-accept so fixtures need not mint jtis."""
    from btagent_backend.auth.middleware import _assert_token_not_revoked

    _patch_settings(monkeypatch, Settings(env="test"))
    await _assert_token_not_revoked(_legacy_payload())  # must not raise


# ---------------------------------------------------------------------------
# P1.1 — the S3 validator covers BOTH halves of the credential pair
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", (*_PROD_SPELLINGS, "staging"))
def test_default_s3_access_key_rejected_outside_dev(spelling: str) -> None:
    with pytest.raises(ValueError, match="BTAGENT_S3_ACCESS_KEY"):
        _prod_settings(spelling, s3_access_key="minioadmin")


@pytest.mark.parametrize("spelling", (*_PROD_SPELLINGS, "staging"))
def test_default_s3_secret_key_rejected_outside_dev(spelling: str) -> None:
    """Half a rotated credential pair is not a rotated credential.

    The original validator only checked ``s3_access_key``, so rotating the
    access key while leaving ``BTAGENT_S3_SECRET_KEY=minioadmin`` (the MinIO
    default shipped in ``infra/.env.example``) booted clean — with the
    chain-of-custody evidence bucket still on a publicly-known password.
    """
    with pytest.raises(ValueError, match="BTAGENT_S3_SECRET_KEY"):
        _prod_settings(spelling, s3_secret_key="minioadmin")


@pytest.mark.parametrize("env", ["dev", "test"])
def test_default_s3_credentials_allowed_in_dev_and_test(env: str) -> None:
    """Local MinIO defaults must keep working — CI boots with them."""
    settings = Settings(env=env)
    assert settings.s3_access_key == "minioadmin"
    assert settings.s3_secret_key == "minioadmin"
