"""Tests for the Investigation CRUD and lifecycle API endpoints."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow, UserRow
from btagent_shared.types.enums import InvestigationStatus
from btagent_shared.utils.ids import generate_id
from helpers import auth_header


# ---- POST /api/v1/investigations ----

@pytest.mark.asyncio
async def test_create_investigation_returns_201(
    client: AsyncClient, analyst_token: str
):
    """Creating an investigation returns 201 with the new resource."""
    resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={
            "title": "Suspicious lateral movement",
            "description": "Detected unusual RDP connections from workstation WS-042.",
            "severity": "high",
            "tlp_level": "amber",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["title"] == "Suspicious lateral movement"
    assert body["id"].startswith("inv_")


@pytest.mark.asyncio
async def test_create_investigation_defaults_pending(
    client: AsyncClient, analyst_token: str
):
    """A newly created investigation defaults to status=pending."""
    resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "Default status check"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "pending"


@pytest.mark.asyncio
async def test_create_investigation_defaults_severity(
    client: AsyncClient, analyst_token: str
):
    """A newly created investigation without severity defaults to medium."""
    resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "Severity default check"},
    )
    assert resp.status_code == 201
    assert resp.json()["severity"] == "medium"


@pytest.mark.asyncio
async def test_create_investigation_defaults_tlp(
    client: AsyncClient, analyst_token: str
):
    """A newly created investigation without tlp_level defaults to green."""
    resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "TLP default check"},
    )
    assert resp.status_code == 201
    assert resp.json()["tlp_level"] == "green"


# ---- GET /api/v1/investigations ----

@pytest.mark.asyncio
async def test_list_investigations_paginated(
    client: AsyncClient, analyst_token: str
):
    """Listing investigations returns a paginated response."""
    # Create a few investigations first.
    for i in range(3):
        await client.post(
            "/api/v1/investigations",
            headers=auth_header(analyst_token),
            json={"title": f"List test inv {i}"},
        )

    resp = await client.get(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert "total" in body
    assert "page" in body
    assert "page_size" in body
    assert body["total"] >= 3
    assert len(body["items"]) <= body["page_size"]


@pytest.mark.asyncio
async def test_list_investigations_with_status_filter(
    client: AsyncClient, analyst_token: str
):
    """Filtering by status returns only matching investigations."""
    # Create one pending investigation.
    await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "Filter test pending"},
    )

    resp = await client.get(
        "/api/v1/investigations?status=pending",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    for item in body["items"]:
        assert item["status"] == "pending"


@pytest.mark.asyncio
async def test_list_investigations_nonexistent_status(
    client: AsyncClient, analyst_token: str
):
    """Filtering with a status that no investigation has returns empty list."""
    resp = await client.get(
        "/api/v1/investigations?status=closed",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    # Might be empty or contain only closed ones (none were created as closed).
    for item in body["items"]:
        assert item["status"] == "closed"


# ---- GET /api/v1/investigations/{id} ----

@pytest.mark.asyncio
async def test_get_investigation_by_id(
    client: AsyncClient, analyst_token: str
):
    """Fetching an investigation by ID returns the correct record."""
    create_resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "Get by ID test", "severity": "critical"},
    )
    inv_id = create_resp.json()["id"]

    resp = await client.get(
        f"/api/v1/investigations/{inv_id}",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == inv_id
    assert body["title"] == "Get by ID test"
    assert body["severity"] == "critical"


@pytest.mark.asyncio
async def test_get_nonexistent_investigation_returns_404(
    client: AsyncClient, analyst_token: str
):
    """Requesting a non-existent investigation ID returns 404."""
    resp = await client.get(
        "/api/v1/investigations/inv_does_not_exist",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---- POST /api/v1/investigations/{id}/chat ----

@pytest.mark.asyncio
async def test_chat_accepts_message(
    client: AsyncClient, analyst_token: str
):
    """Posting a chat message to an investigation returns status=sent."""
    create_resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={"title": "Chat test"},
    )
    inv_id = create_resp.json()["id"]

    resp = await client.post(
        f"/api/v1/investigations/{inv_id}/chat",
        headers=auth_header(analyst_token),
        json={"message": "What IPs were involved?"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "sent"
    assert body["investigation_id"] == inv_id
    assert body["message"] == "What IPs were involved?"


@pytest.mark.asyncio
async def test_chat_nonexistent_investigation_returns_404(
    client: AsyncClient, analyst_token: str
):
    """Chat to a non-existent investigation returns 404."""
    resp = await client.post(
        "/api/v1/investigations/inv_fake_id/chat",
        headers=auth_header(analyst_token),
        json={"message": "hello"},
    )
    assert resp.status_code == 404


# ---- POST /api/v1/investigations/{id}/pause ----

@pytest.mark.asyncio
async def test_pause_investigation(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user: UserRow
):
    """Pausing a running investigation sets status to paused."""
    # We need an investigation in INVESTIGATING status. Insert directly in DB.
    inv = InvestigationRow(
        id=generate_id("inv"),
        title="Pausable investigation",
        status=InvestigationStatus.INVESTIGATING.value,
        severity="medium",
        tlp_level="green",
        assigned_to=sample_user.id,
    )
    db_session.add(inv)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/investigations/{inv.id}/pause",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "paused"


# ---- POST /api/v1/investigations/{id}/stop ----

@pytest.mark.asyncio
async def test_stop_investigation_sets_cancelled(
    client: AsyncClient, admin_token: str, db_session: AsyncSession, admin_user: UserRow
):
    """Stopping an investigation sets its status to cancelled."""
    # senior_analyst or higher can stop. Admin qualifies.
    inv = InvestigationRow(
        id=generate_id("inv"),
        title="Stoppable investigation",
        status=InvestigationStatus.INVESTIGATING.value,
        severity="high",
        tlp_level="green",
        assigned_to=admin_user.id,
    )
    db_session.add(inv)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/investigations/{inv.id}/stop",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


# ---- Unauthenticated access ----

@pytest.mark.asyncio
async def test_unauthenticated_list_blocked(client: AsyncClient):
    """GET /investigations without a token is blocked."""
    resp = await client.get("/api/v1/investigations")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_create_blocked(client: AsyncClient):
    """POST /investigations without a token is blocked."""
    resp = await client.post(
        "/api/v1/investigations",
        json={"title": "Should fail"},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_get_by_id_blocked(client: AsyncClient):
    """GET /investigations/{id} without a token is blocked."""
    resp = await client.get("/api/v1/investigations/inv_anything")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_unauthenticated_chat_blocked(client: AsyncClient):
    """POST /investigations/{id}/chat without a token is blocked."""
    resp = await client.post(
        "/api/v1/investigations/inv_anything/chat",
        json={"message": "test"},
    )
    assert resp.status_code in (401, 403)
