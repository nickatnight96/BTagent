"""Regression tests for the dedicated webhook secret (SEC #372).

Bug: ``_verify_secret`` used ``getattr(settings, "webhook_secret", None) or
settings.jwt_secret`` — but no ``webhook_secret`` field existed, so it ALWAYS
fell back to the JWT signing key. Any holder of the webhook secret (embedded in
every SIEM/EDR alert-action config) could therefore forge admin JWTs.

Fix contract exercised here:
  * outside dev/test, a webhook request presenting the *jwt_secret* is REJECTED
    (401) — the JWT key is never a valid webhook credential;
  * a request presenting the configured *webhook_secret* is accepted (202);
  * dev/test keep the jwt_secret fallback (unset ``webhook_secret``) so the
    existing local/CI webhook flow still works;
  * ``Settings`` refuses to start (outside dev/test) when ``webhook_secret``
    equals ``jwt_secret``.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from btagent_backend.config import Settings, get_settings

_SPLUNK_PATH = "/api/v1/webhooks/splunk"

# Distinct strong secrets for the prod-like ("staging") settings below. The
# whole point of the fix is that these two are NOT interchangeable.
_JWT_SECRET = "j" * 64
_WEBHOOK_SECRET = "w" * 64
_REAL_S3_KEY = "real-prod-access-key"

# The jwt_secret the conftest test environment runs with — used to prove the
# dev/test fallback still authenticates.
_TEST_JWT_SECRET = "test-secret-key-for-jwt-signing-only"


def _prod_like_settings(**overrides: object) -> Settings:
    """Build a non-dev/test ``Settings`` with only the webhook validator armed.

    ``env="staging"`` fires the jwt/s3/webhook validators but NOT the CORS one
    (which is prod-only), so we don't have to supply a CORS allowlist.
    """
    base: dict[str, object] = {
        "env": "staging",
        "jwt_secret": _JWT_SECRET,
        "s3_access_key": _REAL_S3_KEY,
        "webhook_secret": _WEBHOOK_SECRET,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest_asyncio.fixture()
async def prod_client():
    """``AsyncClient`` wired to the app with prod-like (staging) settings.

    Uses a DEDICATED in-memory SQLite engine with ``StaticPool`` (a single
    shared connection) so the schema is always present regardless of how the
    shared session-wide engine's pool is interleaved by the rest of the suite.
    Overrides ``get_db`` with this engine's session and ``get_settings`` with a
    prod-like Settings whose ``webhook_secret`` differs from ``jwt_secret``.
    ``Base.metadata`` has already been made SQLite-compatible by conftest
    (JSONB → JSON, PG-only indexes dropped) at import time.
    """
    from btagent_backend.api.deps import get_db
    from btagent_backend.db.models import DEFAULT_ORG_ID, Base, OrganizationRow
    from btagent_backend.main import create_app

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as seed:
        seed.add(OrganizationRow(id=DEFAULT_ORG_ID, name="Default Organization"))
        await seed.commit()

    async def _get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    settings = _prod_like_settings()

    app = create_app()
    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_settings] = lambda: settings

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac
    finally:
        await engine.dispose()


# --- HTTP behaviour (the core regression) ---------------------------------


@pytest.mark.asyncio
async def test_webhook_rejects_jwt_secret_in_prod(prod_client: AsyncClient) -> None:
    """Presenting the JWT signing key as the webhook secret is REJECTED (401)."""
    resp = await prod_client.post(
        _SPLUNK_PATH,
        headers={"X-Webhook-Secret": _JWT_SECRET},
        json={"search_name": "forged", "severity": "high"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_accepts_configured_secret_in_prod(prod_client: AsyncClient) -> None:
    """Presenting the configured webhook secret is accepted (202)."""
    resp = await prod_client.post(
        _SPLUNK_PATH,
        headers={"X-Webhook-Secret": _WEBHOOK_SECRET},
        json={"search_name": "legit", "severity": "high"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["investigation_id"].startswith("inv")


@pytest.mark.asyncio
async def test_webhook_rejects_missing_secret_in_prod(prod_client: AsyncClient) -> None:
    """No secret at all is still rejected (401)."""
    resp = await prod_client.post(
        _SPLUNK_PATH,
        json={"search_name": "anon", "severity": "low"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_dev_test_falls_back_to_jwt_secret(client: AsyncClient) -> None:
    """Dev/test convenience: with webhook_secret unset, jwt_secret still works.

    Uses the default conftest ``client`` (env=test, webhook_secret unset), so
    this locks in that the fix does NOT break the existing dev/CI webhook flow.
    """
    resp = await client.post(
        _SPLUNK_PATH,
        headers={"X-Webhook-Secret": _TEST_JWT_SECRET},
        json={"search_name": "fallback", "severity": "low"},
    )
    assert resp.status_code == 202


# --- Config validator ------------------------------------------------------


def test_config_rejects_webhook_secret_equal_to_jwt() -> None:
    """Outside dev/test, webhook_secret == jwt_secret is a fatal misconfig."""
    with pytest.raises(ValueError, match="BTAGENT_WEBHOOK_SECRET"):
        _prod_like_settings(webhook_secret=_JWT_SECRET)


def test_config_allows_distinct_webhook_secret() -> None:
    """A distinct, strong webhook secret is accepted outside dev/test."""
    settings = _prod_like_settings()
    assert settings.webhook_secret == _WEBHOOK_SECRET


def test_config_test_env_allows_unset_webhook_secret() -> None:
    """Test env must construct fine with webhook_secret unset (CI boot)."""
    settings = Settings(env="test")
    assert settings.webhook_secret is None
