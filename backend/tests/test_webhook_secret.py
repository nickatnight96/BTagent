"""Regression tests for the dedicated webhook secret (SEC #372 + P1.1).

Bug: ``_verify_secret`` used ``getattr(settings, "webhook_secret", None) or
settings.jwt_secret`` — but no ``webhook_secret`` field existed, so it ALWAYS
fell back to the JWT signing key. Any holder of the webhook secret (embedded in
every SIEM/EDR alert-action config) could therefore forge admin JWTs.

The first fix left a dev/test carve-out that kept the ``jwt_secret`` fallback
"for local convenience". P1.1 removes it: the shipped ``infra/.env`` sets
``BTAGENT_ENV=dev``, so that carve-out reproduced the original vulnerability on
every stock install. There is now NO fallback in ANY environment.

Fix contract exercised here:
  * a webhook request presenting the *jwt_secret* is REJECTED (401) — the JWT
    key is never a valid webhook credential, in any environment;
  * a request presenting the configured *webhook_secret* is accepted (202);
  * an UNSET ``webhook_secret`` fails closed (401) everywhere, dev/test
    included — webhook ingestion is simply off until a secret is configured;
  * ``Settings`` refuses to start (outside dev/test) when ``webhook_secret``
    equals ``jwt_secret``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

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
_REAL_S3_SECRET = "real-prod-secret-key"

# The jwt_secret the conftest test environment runs with — used to prove that
# even in env=test it is NOT accepted as a webhook credential.
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
        "s3_secret_key": _REAL_S3_SECRET,
        "webhook_secret": _WEBHOOK_SECRET,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@asynccontextmanager
async def _client_with_settings(settings: Settings):
    """``AsyncClient`` wired to the app with the supplied ``Settings``.

    Uses a DEDICATED in-memory SQLite engine with ``StaticPool`` (a single
    shared connection) so the schema is always present regardless of how the
    shared session-wide engine's pool is interleaved by the rest of the suite.
    Overrides ``get_db`` with this engine's session and ``get_settings`` with
    the caller's. ``Base.metadata`` has already been made SQLite-compatible by
    conftest (JSONB → JSON, PG-only indexes dropped) at import time.
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

    app = create_app()
    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_settings] = lambda: settings

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac
    finally:
        await engine.dispose()


@pytest_asyncio.fixture()
async def prod_client():
    """Client running prod-like (staging) settings with a distinct webhook secret."""
    async with _client_with_settings(_prod_like_settings()) as ac:
        yield ac


@pytest_asyncio.fixture()
async def test_env_webhook_client():
    """Client running ``env=test`` with an EXPLICITLY configured webhook secret.

    The supported local/CI webhook path now that the ``jwt_secret`` fallback is
    gone: dev and test configure ``BTAGENT_WEBHOOK_SECRET`` like every other
    environment.
    """
    settings = Settings(env="test", webhook_secret=_WEBHOOK_SECRET)
    async with _client_with_settings(settings) as ac:
        yield ac


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
async def test_webhook_rejects_jwt_secret_in_test_env(client: AsyncClient) -> None:
    """P1.1: the dev/test jwt_secret fallback is GONE — 401, not 202.

    This test previously asserted the opposite (``202``), locking in the
    carve-out that re-created #372 on every stock install: ``infra/.env`` ships
    ``BTAGENT_ENV=dev``, so "dev/test only" meant "everywhere anyone actually
    runs this". Uses the default conftest ``client`` (env=test,
    ``webhook_secret`` unset) and presents the env's JWT signing key.
    """
    resp = await client.post(
        _SPLUNK_PATH,
        headers={"X-Webhook-Secret": _TEST_JWT_SECRET},
        json={"search_name": "fallback", "severity": "low"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_unset_secret_denies_in_test_env(client: AsyncClient) -> None:
    """An unset webhook secret fails closed in test env too — no secret works."""
    for candidate in (None, "", "guess", _TEST_JWT_SECRET):
        headers = {} if candidate is None else {"X-Webhook-Secret": candidate}
        resp = await client.post(
            _SPLUNK_PATH,
            headers=headers,
            json={"search_name": "closed", "severity": "low"},
        )
        assert resp.status_code == 401, candidate


@pytest.mark.asyncio
async def test_webhook_accepts_configured_secret_in_test_env(
    test_env_webhook_client: AsyncClient,
) -> None:
    """The supported dev/CI path: configure BTAGENT_WEBHOOK_SECRET explicitly.

    Removing the fallback must not remove the *ability* to run webhooks
    locally — it only removes the JWT-key shortcut. With an explicit secret
    configured, env=test ingests exactly as staging/prod does. This is what the
    UAT harness now does instead of sending ``$BTAGENT_JWT_SECRET``.
    """
    resp = await test_env_webhook_client.post(
        _SPLUNK_PATH,
        headers={"X-Webhook-Secret": _WEBHOOK_SECRET},
        json={"search_name": "configured", "severity": "low"},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["investigation_id"].startswith("inv")


# --- Config validator ------------------------------------------------------


def test_blank_env_value_reads_as_unset() -> None:
    """``BTAGENT_WEBHOOK_SECRET=`` (blank, as shipped in .env.example) is unset.

    An env file cannot express ``None``; a present-but-empty key yields ``""``.
    It must normalise to ``None`` so the startup warning and the request-path
    error both say "not configured" rather than "mismatch".
    """
    assert Settings(env="test", webhook_secret="").webhook_secret is None
    assert Settings(env="test", webhook_secret="   ").webhook_secret is None


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
