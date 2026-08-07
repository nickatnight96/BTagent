"""Tests for the TLP egress policy CRUD API (EPIC-7 UC-7.2)."""

from __future__ import annotations

import pytest_asyncio
from btagent_shared.security.tlp_policy import POLICY_ENFORCED_EGRESS_KINDS, EgressKind
from httpx import AsyncClient
from sqlalchemy import delete, select

from btagent_backend.db.models import AuditLogRow, TLPPolicyRow
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
    resp = await client.post("/api/v1/tlp-policies", json=bad, headers=auth_header(admin_token))
    assert resp.status_code == 422


async def test_create_rejects_unknown_egress_kind(client: AsyncClient, admin_token: str):
    bad = {"action": "allow", "egress_kinds": ["carrier_pigeon"]}
    resp = await client.post("/api/v1/tlp-policies", json=bad, headers=auth_header(admin_token))
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


async def test_evaluate_rejects_unknown_egress_kind(client: AsyncClient, admin_token: str):
    resp = await client.post(
        "/api/v1/tlp-policies/evaluate",
        json={"tlp": "red", "egress_kind": "carrier_pigeon"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422


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


# --- enforced vs advisory channels ----------------------------------------- #


async def test_evaluate_says_when_the_decision_is_not_applied(
    client: AsyncClient, admin_token: str
):
    """The dry-run answers identically for a channel with no gate.

    ``mcp_return`` returns the same shape and the same ``allowed`` as
    ``stix_export`` — that is the whole problem, and why the response has to
    carry the distinction rather than leaving the reader to infer it.
    """
    enforced = await client.post(
        "/api/v1/tlp-policies/evaluate",
        json={"tlp": "red", "egress_kind": "stix_export"},
        headers=auth_header(admin_token),
    )
    advisory = await client.post(
        "/api/v1/tlp-policies/evaluate",
        json={"tlp": "red", "egress_kind": "mcp_return"},
        headers=auth_header(admin_token),
    )
    assert enforced.status_code == advisory.status_code == 200

    # Indistinguishable on the decision itself...
    assert enforced.json()["allowed"] == advisory.json()["allowed"] is False
    # ...and distinguishable only because of the new field.
    assert enforced.json()["policy_enforced"] is True
    assert advisory.json()["policy_enforced"] is False


async def test_egress_kinds_endpoint_serves_the_whole_vocabulary(
    client: AsyncClient, admin_token: str
):
    """Every channel, labelled — the SPA renders its picker from this.

    Compared against the enum rather than a hand-written list here for the
    same reason the endpoint exists: a second copy is what went stale.
    """
    resp = await client.get("/api/v1/tlp-policies/egress-kinds", headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    rows = resp.json()

    assert [r["kind"] for r in rows] == [k.value for k in EgressKind]
    enforced = {r["kind"] for r in rows if r["policy_enforced"]}
    assert enforced == {k.value for k in POLICY_ENFORCED_EGRESS_KINDS}


async def test_egress_kinds_requires_view(client: AsyncClient, analyst_token: str):
    """Where the enforcement gaps are is not public information."""
    resp = await client.get("/api/v1/tlp-policies/egress-kinds", headers=auth_header(analyst_token))
    assert resp.status_code == 403


async def test_egress_kinds_is_not_swallowed_by_the_id_route(client: AsyncClient, admin_token: str):
    """``/egress-kinds`` must not be read as a policy id.

    ``DELETE /{policy_id}`` is a different method so there is no live
    conflict, but adding ``GET /{policy_id}`` later would silently turn this
    endpoint into a 404 lookup for a policy named "egress-kinds". Pinning it
    now makes that a test failure instead of a blank picker.
    """
    resp = await client.get("/api/v1/tlp-policies/egress-kinds", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_creating_an_advisory_policy_records_that_on_the_ledger(
    client: AsyncClient, admin_token: str, db_session
):
    """The approval is a governance fact; so is its being partly inert."""
    created = await client.post(
        "/api/v1/tlp-policies",
        json={
            "action": "deny",
            "egress_kinds": ["stix_export", "mcp_return"],
            "applies_to_tlp": ["amber_strict"],
            "rationale": "No connector returns of AMBER_STRICT.",
        },
        headers=auth_header(admin_token),
    )
    assert created.status_code == 201, created.text

    entry = (
        await db_session.execute(
            select(AuditLogRow)
            .where(AuditLogRow.resource == created.json()["id"])
            .where(AuditLogRow.action == "tlp_policy_created")
        )
    ).scalar_one()
    assert entry.details["advisory_egress_kinds"] == ["mcp_return"]


async def test_a_policy_naming_only_enforced_channels_records_none(
    client: AsyncClient, admin_token: str, db_session
):
    created = await client.post(
        "/api/v1/tlp-policies", json=_allow_red_stix(), headers=auth_header(admin_token)
    )
    entry = (
        await db_session.execute(
            select(AuditLogRow)
            .where(AuditLogRow.resource == created.json()["id"])
            .where(AuditLogRow.action == "tlp_policy_created")
        )
    ).scalar_one()
    assert entry.details["advisory_egress_kinds"] == []


async def test_an_any_channel_policy_records_both_advisory_channels(
    client: AsyncClient, admin_token: str, db_session
):
    """Empty ``egress_kinds`` means *any* channel, so it covers the inert two.

    This is the case an intersection-only reading gets backwards: the widest
    policy in the system would be recorded as fully enforced.
    """
    created = await client.post(
        "/api/v1/tlp-policies",
        json={"action": "deny", "applies_to_tlp": ["red"], "rationale": "blanket"},
        headers=auth_header(admin_token),
    )
    assert created.status_code == 201, created.text
    entry = (
        await db_session.execute(
            select(AuditLogRow)
            .where(AuditLogRow.resource == created.json()["id"])
            .where(AuditLogRow.action == "tlp_policy_created")
        )
    ).scalar_one()
    assert entry.details["advisory_egress_kinds"] == ["mcp_return", "event_emit"]
