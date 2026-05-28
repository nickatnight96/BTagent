"""Tests for the /health (liveness) and /health/ready (readiness) endpoints.

All deep-readiness tests MOCK the DB / Redis / S3 clients — they never require
live infrastructure (CI has Postgres + Redis but no MinIO/S3).
"""

import pytest
from httpx import AsyncClient

import btagent_backend.api.v1.health as health_mod


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient):
    """GET /health should return 200 with status ok."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


@pytest.mark.asyncio
async def test_health_includes_version(client: AsyncClient):
    """GET /health should include the application version string."""
    resp = await client.get("/health")
    body = resp.json()
    assert "version" in body
    assert body["version"] == "0.1.0"


@pytest.mark.asyncio
async def test_health_includes_env(client: AsyncClient):
    """GET /health should report the current environment."""
    resp = await client.get("/health")
    body = resp.json()
    assert "env" in body


@pytest.mark.asyncio
async def test_health_includes_database_field(client: AsyncClient):
    """GET /health should include a database connectivity field."""
    resp = await client.get("/health")
    body = resp.json()
    assert "database" in body
    # With the test SQLite backend the DB check should succeed.
    assert body["database"] == "connected"


@pytest.mark.asyncio
async def test_health_does_not_touch_s3(client: AsyncClient, monkeypatch):
    """Shallow /health must NOT probe S3/MinIO (CI has no MinIO).

    If the liveness probe ever calls the S3 check, this blows up — guarding the
    CI ``curl --fail http://localhost:8000/health`` startup gate.
    """

    def _boom() -> bool:
        raise AssertionError("/health must not probe S3")

    monkeypatch.setattr(health_mod, "_check_s3", _boom)
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert "s3" not in body


@pytest.mark.asyncio
async def test_readiness_all_healthy(client: AsyncClient, monkeypatch):
    """GET /health/ready returns 200 when DB, Redis and S3 are all healthy.

    DB runs against the SQLite test engine; Redis and S3 checks are mocked.
    """

    async def _ok() -> bool:
        return True

    monkeypatch.setattr(health_mod, "_check_redis", lambda: _ok())
    monkeypatch.setattr(health_mod, "_check_s3", lambda: _ok())

    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"] == {"db": "ok", "redis": "ok", "s3": "ok"}


@pytest.mark.asyncio
async def test_readiness_redis_down_returns_503(client: AsyncClient, monkeypatch):
    """GET /health/ready returns 503 and flags Redis when its check raises."""

    async def _ok() -> bool:
        return True

    async def _redis_fail() -> bool:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(health_mod, "_check_redis", lambda: _redis_fail())
    monkeypatch.setattr(health_mod, "_check_s3", lambda: _ok())

    resp = await client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["redis"] == "down"
    # Other deps stay healthy and independently reported.
    assert body["checks"]["db"] == "ok"
    assert body["checks"]["s3"] == "ok"


@pytest.mark.asyncio
async def test_readiness_s3_down_returns_503(client: AsyncClient, monkeypatch):
    """GET /health/ready returns 503 and flags S3 when its check raises."""

    async def _ok() -> bool:
        return True

    async def _s3_fail() -> bool:
        raise RuntimeError("bucket head failed")

    monkeypatch.setattr(health_mod, "_check_redis", lambda: _ok())
    monkeypatch.setattr(health_mod, "_check_s3", lambda: _s3_fail())

    resp = await client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["s3"] == "down"
    assert body["checks"]["db"] == "ok"
    assert body["checks"]["redis"] == "ok"
