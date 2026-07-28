"""Tests for the unified long-term Agent Memory layer (#482) — FOUNDATIONAL.

Covers the store + service (record/recall, upsert dedup, strict org-scoping,
TLP-aware recall), the ``<agent-memory>`` prompt rendering, the best-effort
investigation-close auto-write hook, and the RBAC-gated API.

Count-sensitive tests seed a dedicated per-test org (``generate_id("org")``)
rather than ``DEFAULT_ORG_ID`` — the backend suite shares one session-scoped
in-memory SQLite whose committed rows persist across tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from btagent_shared.types.config import TLP
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import InvestigationRow, OrganizationRow
from btagent_backend.db.models_memory import AgentMemoryRow
from btagent_backend.services.memory_service import (
    MemoryService,
    record_investigation_close_memories,
    render_for_prompt,
)
from tests.helpers import auth_header

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def fresh_org(db_session):
    """Create and return a dedicated per-test org id (FK target for memories)."""
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"Memory Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return oid


@pytest_asyncio.fixture()
async def two_orgs(db_session):
    """Create two dedicated orgs for cross-tenant isolation tests."""
    a, b = generate_id("org"), generate_id("org")
    for oid in (a, b):
        db_session.add(OrganizationRow(id=oid, name=f"Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return a, b


# --------------------------------------------------------------------------- #
# record + recall
# --------------------------------------------------------------------------- #


async def test_record_and_recall(db_session, fresh_org):
    svc = MemoryService()
    row = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="10.0.0.5",
        content="Primary domain controller",
        source="inv_test",
        confidence=0.9,
    )
    await db_session.commit()

    assert row.id.startswith("mem_")

    recalled = await svc.recall_memories(db_session, fresh_org, subject="10.0.0.5")
    assert len(recalled) == 1
    assert recalled[0].content == "Primary domain controller"
    assert recalled[0].confidence == 0.9
    assert recalled[0].kind == "entity_note"


async def test_recall_filters_by_kind(db_session, fresh_org):
    svc = MemoryService()
    await svc.record_memory(
        db_session, org_id=fresh_org, kind="entity_note", subject="hostA", content="a note"
    )
    await svc.record_memory(
        db_session, org_id=fresh_org, kind="decision", subject="hostA", content="a decision"
    )
    await db_session.commit()

    notes = await svc.recall_memories(db_session, fresh_org, subject="hostA", kind="entity_note")
    assert len(notes) == 1
    assert notes[0].kind == "entity_note"

    both = await svc.recall_memories(db_session, fresh_org, subject="hostA")
    assert len(both) == 2


async def test_record_rejects_unknown_kind(db_session, fresh_org):
    with pytest.raises(ValueError):
        await MemoryService().record_memory(
            db_session, org_id=fresh_org, kind="bogus", subject="x", content="y"
        )


# --------------------------------------------------------------------------- #
# upsert dedup on (org, kind, subject)
# --------------------------------------------------------------------------- #


async def test_upsert_dedups_on_org_kind_subject(db_session, fresh_org):
    svc = MemoryService()
    first = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="user@corp.test",
        content="initial",
        confidence=0.3,
    )
    await db_session.commit()

    second = await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="user@corp.test",
        content="updated after more evidence",
        confidence=0.8,
    )
    await db_session.commit()

    # Same row reused (upsert), not a duplicate insert.
    assert second.id == first.id

    recalled = await svc.recall_memories(db_session, fresh_org, subject="user@corp.test")
    assert len(recalled) == 1
    assert recalled[0].content == "updated after more evidence"
    assert recalled[0].confidence == 0.8
    # updated_at bumped to at or after created_at.
    assert recalled[0].updated_at >= recalled[0].created_at


# --------------------------------------------------------------------------- #
# strict org-scoping
# --------------------------------------------------------------------------- #


async def test_org_scoping_isolation(db_session, two_orgs):
    org_a, org_b = two_orgs
    svc = MemoryService()

    await svc.record_memory(
        db_session,
        org_id=org_a,
        kind="entity_note",
        subject="shared-subject",
        content="org A only fact",
    )
    await db_session.commit()

    # Org B must never see org A's memory.
    b_recall = await svc.recall_memories(db_session, org_b, subject="shared-subject")
    assert b_recall == []

    a_recall = await svc.recall_memories(db_session, org_a, subject="shared-subject")
    assert len(a_recall) == 1
    assert a_recall[0].content == "org A only fact"


# --------------------------------------------------------------------------- #
# TLP-aware recall
# --------------------------------------------------------------------------- #


async def test_tlp_filtering_withholds_red_from_green_clearance(db_session, fresh_org):
    svc = MemoryService()
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="green-host",
        content="green fact",
        tlp_level=TLP.GREEN,
    )
    await svc.record_memory(
        db_session,
        org_id=fresh_org,
        kind="entity_note",
        subject="red-host",
        content="restricted fact",
        tlp_level=TLP.RED,
    )
    await db_session.commit()

    # GREEN-clearance recall must withhold the RED memory.
    green_recall = await svc.recall_memories(db_session, fresh_org, caller_tlp=TLP.GREEN)
    subjects = {m.subject for m in green_recall}
    assert "green-host" in subjects
    assert "red-host" not in subjects

    # RED-clearance recall sees both.
    red_recall = await svc.recall_memories(db_session, fresh_org, caller_tlp=TLP.RED)
    red_subjects = {m.subject for m in red_recall}
    assert {"green-host", "red-host"} <= red_subjects


# --------------------------------------------------------------------------- #
# render_for_prompt output shape
# --------------------------------------------------------------------------- #


def test_render_for_prompt_shape():
    rows = [
        AgentMemoryRow(
            id="mem_1",
            org_id="org_x",
            kind="entity_note",
            subject="10.0.0.5",
            content="domain controller",
            source="inv_9",
            confidence=0.9,
            tlp_level="green",
        ),
        AgentMemoryRow(
            id="mem_2",
            org_id="org_x",
            kind="decision",
            subject="inv_9",
            content="closed true_positive",
            source="inv_9",
            confidence=None,
            tlp_level="green",
        ),
    ]
    out = render_for_prompt(rows)
    assert out.startswith("<agent-memory>")
    assert out.rstrip().endswith("</agent-memory>")
    assert "[entity_note] 10.0.0.5: domain controller" in out
    assert "source=inv_9" in out
    assert "confidence=0.90" in out
    assert "[decision] inv_9: closed true_positive" in out


def test_render_for_prompt_empty():
    out = render_for_prompt([])
    assert out.startswith("<agent-memory>")
    assert "No agent memory recorded." in out
    assert out.rstrip().endswith("</agent-memory>")


# --------------------------------------------------------------------------- #
# investigation-close auto-write hook
# --------------------------------------------------------------------------- #


async def test_close_hook_records_entity_notes_and_decision(db_session, fresh_org):
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=fresh_org,
        title="Beaconing host",
        status=InvestigationStatus.CLOSED.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()

    final_state = {
        "status": "closed",
        "severity": "high",
        "iocs": [
            {"type": "ip", "value": "203.0.113.9"},
            {"type": "domain", "value": "evil.example"},
            {"type": "ip", "value": "203.0.113.9"},  # dup — deduped
        ],
    }

    recorded = await record_investigation_close_memories(db_session, inv, final_state)
    await db_session.commit()

    # Two distinct entity notes + one decision memory.
    kinds = [m.kind for m in recorded]
    assert kinds.count("entity_note") == 2
    assert kinds.count("decision") == 1

    svc = MemoryService()
    ip_note = await svc.recall_memories(db_session, fresh_org, subject="203.0.113.9")
    assert len(ip_note) == 1
    assert ip_note[0].kind == "entity_note"
    assert inv.id in ip_note[0].content

    decision = await svc.recall_memories(db_session, fresh_org, subject=inv.id, kind="decision")
    assert len(decision) == 1
    assert "disposition=closed" in decision[0].content


async def test_close_hook_is_best_effort_and_does_not_raise():
    """A recorder exception must be swallowed — it must never sink the close."""
    from btagent_backend.services.task_manager import TaskManager

    tm = TaskManager(redis_url="redis://localhost:6379/0", database_url="sqlite+aiosqlite://")

    # Injected recorder raises — the best-effort wrapper must swallow it.
    tm._close_memory_recorder = AsyncMock(side_effect=RuntimeError("boom"))
    # Must not raise even though the recorder blows up.
    await tm._record_close_memories("inv_boom", {"status": "closed", "iocs": []})
    tm._close_memory_recorder.assert_awaited_once()


async def test_close_hook_invokes_recorder_best_effort():
    """When wired, the close path invokes the injectable recorder with its args."""
    from btagent_backend.services.task_manager import TaskManager

    tm = TaskManager(redis_url="redis://localhost:6379/0", database_url="sqlite+aiosqlite://")
    recorder = AsyncMock()
    tm._close_memory_recorder = recorder

    state = {"status": "closed", "iocs": [{"type": "ip", "value": "198.51.100.7"}]}
    await tm._record_close_memories("inv_wired", state)

    recorder.assert_awaited_once()
    # Called with (investigation_id, final_state).
    call_args = recorder.await_args.args
    assert call_args[0] == "inv_wired"
    assert call_args[1] is state


# --------------------------------------------------------------------------- #
# API (RBAC + org-scoped)
# --------------------------------------------------------------------------- #


async def test_api_record_and_recall(client, admin_token, analyst_token):
    subject = f"api-host-{generate_id('mem')}"
    resp = await client.post(
        "/api/v1/memory",
        headers=auth_header(admin_token),
        json={
            "kind": "learning",
            "subject": subject,
            "content": "benign scheduled telemetry, not C2",
            "source": "analyst",
            "confidence": 0.75,
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["subject"] == subject

    # analyst (memory:read) can recall it back by subject.
    got = await client.get(
        f"/api/v1/memory?subject={subject}",
        headers=auth_header(analyst_token),
    )
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["total"] == 1
    assert body["items"][0]["content"] == "benign scheduled telemetry, not C2"


async def test_api_write_denied_for_analyst(client, analyst_token):
    resp = await client.post(
        "/api/v1/memory",
        headers=auth_header(analyst_token),
        json={"kind": "entity_note", "subject": "x", "content": "y"},
    )
    assert resp.status_code == 403


async def test_api_record_rejects_unknown_kind(client, admin_token):
    resp = await client.post(
        "/api/v1/memory",
        headers=auth_header(admin_token),
        json={"kind": "nonsense", "subject": "x", "content": "y"},
    )
    assert resp.status_code == 422
