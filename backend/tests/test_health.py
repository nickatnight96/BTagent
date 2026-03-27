"""Tests for the /health endpoint."""

import pytest
from httpx import AsyncClient


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
