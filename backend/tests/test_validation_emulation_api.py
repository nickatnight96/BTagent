"""API tests for the sandbox-gated emulation route (#118).

``POST /api/v1/validation/emulate`` drives the sandbox-enforcement service:

* a non-sandbox ``target_env`` → 403 with an audited denial body (no emulator),
* an approved sandbox → 201 with a persisted verdict (mock-first, fires nothing),
* RBAC ``validation:emulate`` (incident_commander) is enforced,
* the persisted run shows up in the history list flagged ``emulated=True``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, UserRow

_COMMANDER_PASSWORD = "Commander-P@ss-789!"


@pytest_asyncio.fixture()
async def commander_token(db_session: AsyncSession) -> str:
    """A JWT for an incident_commander (has ``validation:emulate``)."""
    n = generate_id("usr")
    user = UserRow(
        id=n,
        org_id=DEFAULT_ORG_ID,
        username=f"commander_{n[-8:]}",
        email=f"commander_{n[-8:]}@btagent.test",
        password_hash=hash_password(_COMMANDER_PASSWORD),
        role="incident_commander",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return create_token_pair(user.id, user.username, user.role).access_token


async def test_emulate_sandbox_target_returns_verdict(client, commander_token):
    resp = await client.post(
        "/api/v1/validation/emulate",
        headers=auth_header(commander_token),
        json={
            "technique_id": "T1059.001",
            "target_env": "sandbox",
            "expected_severity": "high",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["emulated"] is True
    assert data["target_env"] == "sandbox"
    assert data["verdicts"], "verdicts payload should be present"
    assert data["verdicts"][0]["verdict"] == "validated"
    techniques = {c["technique_id"] for c in data["coverage_by_technique"]}
    assert "T1059.001" in techniques


async def test_emulate_production_target_is_refused_and_audited(client, commander_token):
    resp = await client.post(
        "/api/v1/validation/emulate",
        headers=auth_header(commander_token),
        json={"technique_id": "T1059.001", "target_env": "production"},
    )
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["status"] == "denied"
    assert detail["target_env"] == "production"
    assert detail["audit_id"].startswith("aud_")
    assert "sandbox" in detail["reason"].lower()


async def test_emulate_unknown_target_defaults_denied(client, commander_token):
    # Omitting target_env → defaults to 'unknown' → refused fail-closed.
    resp = await client.post(
        "/api/v1/validation/emulate",
        headers=auth_header(commander_token),
        json={"technique_id": "T1059.001"},
    )
    assert resp.status_code == 403, resp.text


async def test_emulate_requires_commander_role(client, analyst_token):
    # An analyst lacks validation:emulate → 403 before any emulation.
    resp = await client.post(
        "/api/v1/validation/emulate",
        headers=auth_header(analyst_token),
        json={"technique_id": "T1059.001", "target_env": "sandbox"},
    )
    assert resp.status_code == 403, resp.text


async def test_emulate_requires_auth(client):
    resp = await client.post(
        "/api/v1/validation/emulate",
        json={"technique_id": "T1059.001", "target_env": "sandbox"},
    )
    assert resp.status_code in (401, 403)


async def test_emulated_run_appears_in_history(client, commander_token):
    created = await client.post(
        "/api/v1/validation/emulate",
        headers=auth_header(commander_token),
        json={"technique_id": "T1218.005", "target_env": "sandbox"},
    )
    assert created.status_code == 201, created.text
    created_id = created.json()["id"]

    listed = await client.get("/api/v1/validation/runs", headers=auth_header(commander_token))
    assert listed.status_code == 200, listed.text
    items = {item["id"]: item for item in listed.json()["items"]}
    assert created_id in items
    assert items[created_id]["emulated"] is True
    assert items[created_id]["target_env"] == "sandbox"
