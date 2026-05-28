"""Full-surface validation for the engine-backed vertical slices.

Goes beyond the per-endpoint happy-path tests:

  * Route registration — all three slice endpoints are present in the
    live OpenAPI surface (catches a missing router.include_router).
  * Real auth flow — actually POST /auth/login and drive the slices with
    the *cookie* the server sets (the transport the frontend uses), not
    just the Bearer-token fixture.
  * RBAC matrix — analyst vs admin against each route.
  * Live-path degradation — mock off + no client => 501, not 500.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete

from btagent_backend.db.models import AuditLogRow
from tests.conftest import _ADMIN_PASSWORD, _ANALYST_PASSWORD
from tests.helpers import auth_header


@pytest_asyncio.fixture(autouse=True)
async def _isolate_audit_log(db_session):
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()


@pytest.fixture(autouse=True)
def _mock_engine(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")


# --------------------------------------------------------------------------- #
# Route registration — the full slice surface is mounted
# --------------------------------------------------------------------------- #


async def test_all_slice_routes_registered(client: AsyncClient):
    resp = await client.get("/api/openapi.json")
    # openapi may be at /openapi.json depending on docs config; try both.
    if resp.status_code != 200:
        resp = await client.get("/openapi.json")
    assert resp.status_code == 200, "OpenAPI schema not reachable"
    paths = resp.json()["paths"]
    for route in (
        "/api/v1/hunts/package",
        "/api/v1/hunts/correlate",
        "/api/v1/audit/entries",
        "/api/v1/audit/verify",
        "/api/v1/audit/export",
    ):
        assert route in paths, f"{route} missing from OpenAPI surface"


# --------------------------------------------------------------------------- #
# Real auth flow — login, then drive slices via the cookie the server set
# --------------------------------------------------------------------------- #


async def test_login_then_hunt_package_via_cookie(client: AsyncClient, sample_user):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": _ANALYST_PASSWORD},
    )
    assert login.status_code == 200, login.text
    # httpx's AsyncClient persists Set-Cookie on the client jar, so the next
    # request carries btagent_access automatically — no explicit header.
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": "Indicator 10.1.42.17 seen in advisory AA26-002."},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["extracted_ioc_count"] >= 1


async def test_login_then_correlate_via_cookie(client: AsyncClient, sample_user):
    await client.post(
        "/api/v1/auth/login",
        json={"username": sample_user.username, "password": _ANALYST_PASSWORD},
    )
    resp = await client.post(
        "/api/v1/hunts/correlate",
        json={"entity_type": "ip", "entity_value": "10.1.42.17"},
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["sources_queried"]) >= 3


# --------------------------------------------------------------------------- #
# RBAC matrix
# --------------------------------------------------------------------------- #


async def test_rbac_hunts_analyst_allowed(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/correlate",
        json={"entity_type": "ip", "entity_value": "10.1.42.17"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200


async def test_rbac_audit_view_denied_to_analyst(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/audit/entries", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_rbac_audit_view_allowed_to_admin(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/v1/audit/entries", headers=auth_header(admin_token))
    assert resp.status_code == 200


async def test_rbac_audit_export_denied_to_analyst(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/audit/export", headers=auth_header(analyst_token))
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Live-path degradation — mock off + no client => 501 (graceful), not 500
# --------------------------------------------------------------------------- #


async def test_hunt_package_live_path_returns_501(
    client: AsyncClient, analyst_token: str, monkeypatch
):
    # Turn off connector mock so HuntPackageNode takes the live path; with no
    # connectors wired it raises NotImplementedError -> the handler maps to 501.
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": "10.1.42.17"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 501


async def test_correlate_live_path_returns_501(
    client: AsyncClient, analyst_token: str, monkeypatch
):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    resp = await client.post(
        "/api/v1/hunts/correlate",
        json={"entity_type": "ip", "entity_value": "10.1.42.17"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 501
