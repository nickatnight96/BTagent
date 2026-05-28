"""Tests for the TLP egress policy CRUD API (EPIC-7 UC-7.2)."""

from __future__ import annotations

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete

from btagent_backend.db.models import TLPPolicyRow
from tests.helpers import auth_header


@pytest_asyncio.fixture(autouse=True)
async def _isolate_policies(db_session):
    """Clear tlp_policies before + after each test (shared in-memory DB)."""
    await db_session.execute(delete(TLPPolicyRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(TLPPolicyRow))
    await db_session.commit()


def _allow_red_stix() -> dict:
    return {
        "action": "allow",
        "egress_kinds": ["stix_export"],
        "applies_to_tlp": ["red"],
        "rationale": "Approved sharing channel for partner ISAC.",
    }


# --- RBAC ------------------------------------------------------------------ #


async def test_list_requires_view(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/tlp-policies", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_create_requires_manage(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/tlp-policies", json=_allow_red_stix(), headers=auth_header(analyst_token)
    )
    assert resp.status_code == 403


async def test_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/tlp-policies")
    assert resp.status_code in (401, 403)


# --- create + list + delete ------------------------------------------------ #


async def test_create_then_list(client: AsyncClient, admin_token: str):
    create = await client.post(
        "/api/v1/tlp-policies", json=_allow_red_stix(), headers=auth_header(admin_token)
    )
    assert create.status_code == 201, create.text
    body = create.json()
    assert body["id"].startswith("tpol_")
    assert body["action"] == "allow"
    assert body["applies_to_tlp"] == ["red"]
    assert body["approver_id"]  # stamped with the admin's username

    listed = await client.get("/api/v1/tlp-policies", headers=auth_header(admin_token))
    assert listed.status_code == 200
    ids = [p["id"] for p in listed.json()]
    assert body["id"] in ids


async def test_create_downgrade_requires_target(client: AsyncClient, admin_token: str):
    bad = {"action": "downgrade_then_allow", "applies_to_tlp": ["red"]}  # no downgrade_to
    resp = await client.post(
        "/api/v1/tlp-policies", json=bad, headers=auth_header(admin_token)
    )
    assert resp.status_code == 422


async def test_create_rejects_unknown_egress_kind(client: AsyncClient, admin_token: str):
    bad = {"action": "allow", "egress_kinds": ["carrier_pigeon"]}
    resp = await client.post(
        "/api/v1/tlp-policies", json=bad, headers=auth_header(admin_token)
    )
    assert resp.status_code == 422


async def test_delete_policy(client: AsyncClient, admin_token: str):
    created = (
        await client.post(
            "/api/v1/tlp-policies", json=_allow_red_stix(), headers=auth_header(admin_token)
        )
    ).json()
    delete_resp = await client.delete(
        f"/api/v1/tlp-policies/{created['id']}", headers=auth_header(admin_token)
    )
    assert delete_resp.status_code == 204
    listed = await client.get("/api/v1/tlp-policies", headers=auth_header(admin_token))
    assert created["id"] not in [p["id"] for p in listed.json()]


async def test_delete_unknown_returns_404(client: AsyncClient, admin_token: str):
    resp = await client.delete(
        "/api/v1/tlp-policies/tpol_nonexistent", headers=auth_header(admin_token)
    )
    assert resp.status_code == 404


async def test_delete_requires_manage(client: AsyncClient, admin_token: str, analyst_token: str):
    created = (
        await client.post(
            "/api/v1/tlp-policies", json=_allow_red_stix(), headers=auth_header(admin_token)
        )
    ).json()
    resp = await client.delete(
        f"/api/v1/tlp-policies/{created['id']}", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 403


# --- evaluate -------------------------------------------------------------- #


async def test_evaluate_default_deny_red(client: AsyncClient, admin_token: str):
    # No policies -> baseline default-deny for RED.
    resp = await client.post(
        "/api/v1/tlp-policies/evaluate",
        json={"tlp": "red", "egress_kind": "stix_export"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["allowed"] is False
    assert d["action"] == "deny"


async def test_evaluate_allow_policy_permits_red(client: AsyncClient, admin_token: str):
    created = (
        await client.post(
            "/api/v1/tlp-policies", json=_allow_red_stix(), headers=auth_header(admin_token)
        )
    ).json()
    resp = await client.post(
        "/api/v1/tlp-policies/evaluate",
        json={"tlp": "red", "egress_kind": "stix_export"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    d = resp.json()
    assert d["allowed"] is True
    assert d["matched_policy_id"] == created["id"]


async def test_evaluate_downgrade_lowers_tlp(client: AsyncClient, admin_token: str):
    await client.post(
        "/api/v1/tlp-policies",
        json={
            "action": "downgrade_then_allow",
            "applies_to_tlp": ["red"],
            "downgrade_to": "amber",
            "egress_kinds": ["mcp_return"],
        },
        headers=auth_header(admin_token),
    )
    resp = await client.post(
        "/api/v1/tlp-policies/evaluate",
        json={"tlp": "red", "egress_kind": "mcp_return"},
        headers=auth_header(admin_token),
    )
    d = resp.json()
    assert d["allowed"] is True
    assert d["effective_tlp"] == "amber"
    assert d["action"] == "downgrade_then_allow"
