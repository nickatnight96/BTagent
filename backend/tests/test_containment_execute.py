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


# --------------------------------------------------------------------------- #
# Safelist removal (#106 follow-up) — the safelist was add-only, so a mistaken
# never-block entry permanently shielded a malicious target from containment.
# --------------------------------------------------------------------------- #


async def _add_safelist(client, token, *, entry_type="ip", value="9.9.9.9", reason="typo"):
    resp = await client.post(
        "/api/v1/containment/safelist",
        json={"entry_type": entry_type, "value": value, "reason": reason},
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_removing_an_entry_restores_the_ability_to_block(client: AsyncClient, db_session):
    """The whole point: an entry added by mistake can be undone.

    Before removal the target is refused (the safelist guard fires); after
    removal the same block executes. This is what makes a typo correctable
    rather than a permanent shield over a malicious target.
    """
    _org_id, _user_id, token = await _seed_ic(db_session)
    # A genuinely public IP. The RFC 5737 documentation ranges (192.0.2.x /
    # 198.51.100.x / 203.0.113.x) are all structurally reserved, so the
    # universal baseline would keep refusing the block even after the org row
    # is gone — which would test nothing about removal.
    entry = await _add_safelist(client, token, value="93.184.216.34")

    blocked = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "act_1",
            "ioc_type": "ip",
            "ioc_value": "93.184.216.34",
            "tool": "panorama",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert blocked.status_code == 403, blocked.text

    removed = await client.delete(
        f"/api/v1/containment/safelist/{entry['id']}", headers=auth_header(token)
    )
    assert removed.status_code == 204, removed.text

    now_allowed = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "act_2",
            "ioc_type": "ip",
            "ioc_value": "93.184.216.34",
            "tool": "panorama",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert now_allowed.status_code == 200, now_allowed.text


async def test_removal_is_audited_with_what_stopped_being_protected(
    client: AsyncClient, db_session
):
    """Dropping a never-block guard re-enables containment against a target
    someone deliberately protected — the ledger must say which one."""
    org_id, user_id, token = await _seed_ic(db_session)
    entry = await _add_safelist(client, token, entry_type="domain", value="dns.example.org")

    resp = await client.delete(
        f"/api/v1/containment/safelist/{entry['id']}", headers=auth_header(token)
    )
    assert resp.status_code == 204

    rows = await _audit_rows(db_session, org_id=org_id)
    removals = [r for r in rows if r.action == "safelist_entry_removed"]
    assert len(removals) == 1
    row = removals[0]
    assert row.actor == user_id
    assert row.category == "containment"
    # The value, not merely "an entry", so the ledger is usable as evidence.
    assert row.details["value"] == "dns.example.org"
    assert row.details["entry_type"] == "domain"
    assert "dns.example.org" in row.resource


async def test_removal_cannot_drop_the_universal_baseline(client: AsyncClient, db_session):
    """The shared floor is code, not org rows — removal can't reach it.

    A public resolver is safelisted by the baseline in SafelistPolicy even
    with zero org rows, so there is no entry id to delete and blocking it
    stays refused.
    """
    _org_id, _user_id, token = await _seed_ic(db_session)

    listed = await client.get("/api/v1/containment/safelist", headers=auth_header(token))
    assert listed.json() == []

    still_refused = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "act_3",
            "ioc_type": "ip",
            "ioc_value": "8.8.8.8",
            "tool": "panorama",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert still_refused.status_code == 403, still_refused.text


async def test_removal_of_another_orgs_entry_is_404(client: AsyncClient, db_session):
    """Indistinguishable from 'no such entry' — no cross-tenant probing."""
    _org_a, _user_a, token_a = await _seed_ic(db_session, org_name="Org A")
    _org_b, _user_b, token_b = await _seed_ic(db_session, org_name="Org B")
    theirs = await _add_safelist(client, token_b, value="198.51.100.4")

    resp = await client.delete(
        f"/api/v1/containment/safelist/{theirs['id']}", headers=auth_header(token_a)
    )
    assert resp.status_code == 404

    missing = await client.delete(
        "/api/v1/containment/safelist/safe_does_not_exist", headers=auth_header(token_a)
    )
    assert missing.status_code == 404

    # Org B's entry survived A's attempt.
    still_there = await client.get("/api/v1/containment/safelist", headers=auth_header(token_b))
    assert [e["id"] for e in still_there.json()] == [theirs["id"]]


async def test_removal_requires_containment_execute_scope(
    client: AsyncClient, analyst_token: str, db_session
):
    """An analyst cannot drop a never-block guard."""
    _org_id, _user_id, token = await _seed_ic(db_session)
    entry = await _add_safelist(client, token, value="192.0.2.55")

    resp = await client.delete(
        f"/api/v1/containment/safelist/{entry['id']}", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# A7: the connector→class dispatch map must resolve at import time.
# --------------------------------------------------------------------------- #


def test_every_isolation_route_resolves():
    """Each ``_ISOLATION_ROUTES`` entry names a real module, class and method.

    The Cortex route shipped pointing at a nonexistent ``CortexMCPServer``
    (actual: ``CortexXDRMCPServer``) — an *approved* isolation 500'd with an
    AttributeError, the endpoint stayed uncontained, and no audit row was
    written. A dangling name in this map must fail the suite, not the incident.
    """
    import importlib

    from btagent_backend.services.containment_execute_service import _ISOLATION_ROUTES

    for connector, (module, cls_name, method, _target_kwarg) in _ISOLATION_ROUTES.items():
        cls = getattr(importlib.import_module(module), cls_name, None)
        assert cls is not None, f"{connector}: {module}.{cls_name} does not exist"
        assert callable(getattr(cls, method, None)), f"{connector}: {cls_name}.{method} missing"


# --------------------------------------------------------------------------- #
# A3: a manifest-policy refusal at dispatch is an audited denial, not a 500.
# --------------------------------------------------------------------------- #


async def test_policy_refused_dispatch_records_audited_denial(
    client: AsyncClient, db_session, monkeypatch
):
    """An isolation route whose tool has no manifest capability is refused
    fail-closed — 403 with a hash-chained CONTAINMENT denial row, never an
    unaudited 500 (the A7 failure mode)."""
    from btagent_backend.services import containment_execute_service as svc

    monkeypatch.setitem(
        svc._ISOLATION_ROUTES,
        "crowdstrike",
        (
            "btagent_agents.mcp.servers.crowdstrike_mcp",
            "CrowdStrikeMCPServer",
            "cs_totally_undeclared_tool",
            "hostname",
        ),
    )

    org_id, user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_pol",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    assert "manifest policy" in resp.text.lower()

    rows = await _audit_rows(db_session, org_id=org_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.category == "containment"
    assert row.outcome == "denied"
    assert row.details.get("policy_status") == "undeclared"
