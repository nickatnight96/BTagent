"""Tests for the containment approve→execute→record loop (EPIC-3 #106).

Covers the non-negotiable safety controls:

* execute happy path (mock connector) writes an audit row + captures approver,
* a safelisted target is REFUSED for blocking with an audited denial,
* the ``containment:execute`` RBAC gate (403 without scope),
* org-scoping of the never-block safelist (no cross-tenant read),
* the ``approved`` HITL half of the double-gate (403 when not approved).

Every exact-membership assertion is scoped to a dedicated per-test org
(``generate_id("org")``) so it is immune to rows other tests leave in the
session-scoped in-memory SQLite DB.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import select

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import (
    AuditLogRow,
    OrganizationRow,
    ResponseSafelistRow,
    UserRow,
)
from tests.helpers import auth_header


async def _seed_ic(db_session, *, org_name: str = "IC Org") -> tuple[str, str, str]:
    """Create a fresh org + incident_commander user; return (org_id, user_id, token)."""
    org_id = generate_id("org")
    user_id = generate_id("usr")
    db_session.add(
        OrganizationRow(id=org_id, name=f"{org_name} {org_id}", created_at=datetime.now(UTC))
    )
    db_session.add(
        UserRow(
            id=user_id,
            org_id=org_id,
            username=f"ic_{user_id}",
            email=f"{user_id}@btagent.test",
            password_hash=hash_password("IC-P@ss-123!"),
            role="incident_commander",
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    token = create_token_pair(
        user_id, f"ic_{user_id}", "incident_commander", org_id=org_id
    ).access_token
    return org_id, user_id, token


async def _audit_rows(db_session, *, org_id: str) -> list[AuditLogRow]:
    result = await db_session.execute(
        select(AuditLogRow).where(AuditLogRow.org_id == org_id).order_by(AuditLogRow.seq.asc())
    )
    return list(result.scalars().all())


# --------------------------------------------------------------------------- #
# Safety control #1 (RBAC half): containment:execute required
# --------------------------------------------------------------------------- #


async def test_execute_requires_containment_execute_scope(client: AsyncClient, analyst_token: str):
    """An analyst (no containment:execute) is refused with 403 and runs nothing."""
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_001",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "approved": True,
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403, resp.text


async def test_execute_requires_auth(client: AsyncClient):
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_001",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "approved": True,
        },
    )
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Safety control #1 (HITL half): must already be approved
# --------------------------------------------------------------------------- #


async def test_execute_not_approved_is_rejected(client: AsyncClient, db_session):
    """Holding the scope is not enough — an un-approved action is refused (403)."""
    _org_id, _user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_001",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "approved": False,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    assert "approved" in resp.text.lower()


# --------------------------------------------------------------------------- #
# Safety control #2 + #4: execute happy path (mock connector) audits + approver
# --------------------------------------------------------------------------- #


async def test_execute_response_action_happy_path_records_audit_and_approver(
    client: AsyncClient, db_session
):
    org_id, user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_001",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "description": "Isolate WS-JSMITH-PC to stop spread",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is True
    assert body["outcome"] == "success"
    assert body["approver_id"] == user_id
    # Mock connector was actually exercised — no real egress.
    assert body["tool_response"].get("is_mock") is True
    assert body["audit_id"]

    # Exactly one audit row for this org, stamping the acting user as approver.
    rows = await _audit_rows(db_session, org_id=org_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.category == "containment"
    assert row.action == "execute:isolate_host"
    assert row.actor == user_id
    assert row.outcome == "success"
    assert row.details.get("approver_id") == user_id
    assert row.details.get("tool_response", {}).get("is_mock") is True


# --------------------------------------------------------------------------- #
# Safety control #3 + #4: safelisted target REFUSED for blocking, audited denial
# --------------------------------------------------------------------------- #


async def test_bulk_block_safelisted_target_refused_and_audited(client: AsyncClient, db_session):
    org_id, user_id, token = await _seed_ic(db_session)

    # Operator adds a never-block entry for a public IP that would otherwise block.
    add = await client.post(
        "/api/v1/containment/safelist",
        json={"entry_type": "ip", "value": "45.83.12.7", "reason": "corp egress proxy"},
        headers=auth_header(token),
    )
    assert add.status_code == 201, add.text

    # Attempting to block the safelisted IP must be REFUSED (403), not silently skipped.
    resp = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "mit_001",
            "ioc_type": "ip",
            "ioc_value": "45.83.12.7",
            "tool": "panorama",
            "policy_object": "perimeter-blocklist",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["outcome"] == "denied"
    assert detail["approver_id"] == user_id

    # The denial is a first-class audited fact (outcome=denied), not a silent skip.
    rows = await _audit_rows(db_session, org_id=org_id)
    denials = [r for r in rows if r.outcome == "denied"]
    assert len(denials) == 1
    assert denials[0].action == "execute:block_ioc"
    assert denials[0].details.get("approver_id") == user_id
    assert "safelist" in denials[0].details.get("reason", "").lower()
    # No successful block was recorded.
    assert not [r for r in rows if r.outcome == "success"]


async def test_bulk_block_structurally_reserved_ip_refused(client: AsyncClient, db_session):
    """RFC1918 targets are refused by the universal baseline even with no org entry."""
    org_id, _user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "mit_001",
            "ioc_type": "ip",
            "ioc_value": "10.1.2.3",
            "tool": "panorama",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    rows = await _audit_rows(db_session, org_id=org_id)
    assert [r.outcome for r in rows] == ["denied"]


# --------------------------------------------------------------------------- #
# Safety control #2 + task D: bulk block happy path attaches a change record
# --------------------------------------------------------------------------- #


async def test_bulk_block_happy_path_attaches_change_record(client: AsyncClient, db_session):
    org_id, user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "mit_001",
            "ioc_type": "ip",
            "ioc_value": "185.220.101.42",
            "tool": "panorama",
            "policy_object": "perimeter-blocklist",
            "rollback": "Remove 185.220.101.42 from panorama:perimeter-blocklist",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is True
    assert body["outcome"] == "success"
    # Change-management link attached (mock ServiceNow SIR number).
    assert body["change_ref"] and body["change_ref"].startswith("SIR")

    rows = await _audit_rows(db_session, org_id=org_id)
    success = [r for r in rows if r.outcome == "success"]
    assert len(success) == 1
    assert success[0].details.get("change_ref") == body["change_ref"]
    assert success[0].details.get("approver_id") == user_id


# --------------------------------------------------------------------------- #
# Safety control #5: safelist is org-scoped (no cross-tenant read)
# --------------------------------------------------------------------------- #


async def test_safelist_is_org_scoped(client: AsyncClient, db_session):
    org_a, _ua, token_a = await _seed_ic(db_session, org_name="Org A")
    org_b, _ub, token_b = await _seed_ic(db_session, org_name="Org B")

    # Org A adds an entry.
    add = await client.post(
        "/api/v1/containment/safelist",
        json={"entry_type": "domain", "value": "corp-vpn.example", "reason": "vpn"},
        headers=auth_header(token_a),
    )
    assert add.status_code == 201, add.text

    # Org B must NOT see org A's entry.
    list_b = await client.get("/api/v1/containment/safelist", headers=auth_header(token_b))
    assert list_b.status_code == 200, list_b.text
    assert list_b.json() == []

    # Org A sees exactly its own entry.
    list_a = await client.get("/api/v1/containment/safelist", headers=auth_header(token_a))
    assert list_a.status_code == 200, list_a.text
    values_a = {(e["entry_type"], e["value"]) for e in list_a.json()}
    assert ("domain", "corp-vpn.example") in values_a
    assert all(e["org_id"] == org_a for e in list_a.json())

    # And org B's safelist did not leak org A's block guard: a block that A would
    # refuse, B still allows (proving the guard is per-tenant).
    resp_b = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "mit_x",
            "ioc_type": "domain",
            "ioc_value": "corp-vpn.example",
            "tool": "umbrella",
            "approved": True,
        },
        headers=auth_header(token_b),
    )
    assert resp_b.status_code == 200, resp_b.text
    assert resp_b.json()["outcome"] == "success"

    # Whereas org A refuses the very same block (its safelist governs).
    resp_a = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "mit_y",
            "ioc_type": "domain",
            "ioc_value": "sub.corp-vpn.example",
            "tool": "umbrella",
            "approved": True,
        },
        headers=auth_header(token_a),
    )
    assert resp_a.status_code == 403, resp_a.text

    # DB-level confirmation: A's row is not visible under B's org_id.
    b_rows = await db_session.execute(
        select(ResponseSafelistRow).where(ResponseSafelistRow.org_id == org_b)
    )
    assert list(b_rows.scalars().all()) == []


# --------------------------------------------------------------------------- #
# Safelist input validation
# --------------------------------------------------------------------------- #


async def test_safelist_rejects_bad_entry(client: AsyncClient, db_session):
    _org_id, _user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/safelist",
        json={"entry_type": "ip", "value": "not-an-ip"},
        headers=auth_header(token),
    )
    assert resp.status_code == 422, resp.text
