"""A HITL-gated playbook actually stops, and only the right role can release it.

#588. Two independent defects met here, and either one alone made the control
untestable:

* the stub executor walked every step type straight through, so a playbook with
  a ``hitl_gate`` completed without ever asking a person; and
* ``POST /playbooks/executions/{id}/approve`` did not exist.

The browser test written to prove the gate holds waited on ``awaiting_hitl`` —
a status no code path writes, since the run status is ``paused_hitl`` — so it
took its "did not pause, skipping" branch unconditionally and its body, the
approval probe, had never once executed. Three layers of plausible-looking
green over a control that was not implemented.

**Why the split.** The executor writes through its own session factory from a
background task, which the pytest harness cannot reach — the connection the
task lands on has no schema. That is why the only coverage of "does a gate stop
the run" used to be a browser test, and why a vacuous browser test meant no
coverage at all. So the *decision* (where a walk is allowed to stop) is a pure
function tested here directly, and the *endpoint* is tested against a paused
row seeded through the normal session. Neither needs the background task.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.playbook import PlaybookStatus, StepExecutionStatus
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_playbook import PlaybookExecutionRow, PlaybookRow
from btagent_backend.services.playbook_service import PlaybookService, steps_until_gate

#: A gate in the middle: one step before it must be runnable, one after it must
#: not be. A playbook whose gate is the first step would pass even if "pause"
#: were implemented as "refuse to start".
_GATED_YAML = """\
name: HITL Gated PB
trigger:
  type: manual
steps:
  - id: first
    type: action
    name: Before the gate
    tool_name: enrich_ioc
    next_step: gate
  - id: gate
    type: hitl_gate
    name: Human checkpoint
    prompt: Approve the containment action?
    required_role: senior_analyst
    next_step: after
  - id: after
    type: action
    name: After the gate
    tool_name: enrich_ioc
"""

_UNGATED_YAML = """\
name: Plain PB
trigger:
  type: manual
steps:
  - id: only
    type: action
    name: Just do it
    tool_name: enrich_ioc
"""


# --------------------------------------------------------------------------- #
# The decision: where a walk is allowed to stop
# --------------------------------------------------------------------------- #


def test_the_walk_stops_on_the_gate_and_not_past_it():
    """The regression, as a unit: ``after`` must not be runnable yet.

    Before the fix the executor had no notion of a gate at all, so all three
    steps ran and the automation approved itself.
    """
    definition = PlaybookService().compile_playbook(_GATED_YAML)

    runnable = [s.id for s in steps_until_gate(definition)]

    assert runnable == ["first", "gate"]


def test_an_ungated_playbook_still_runs_end_to_end():
    """The gate logic must not accidentally stop ordinary playbooks."""
    definition = PlaybookService().compile_playbook(_UNGATED_YAML)

    assert [s.id for s in steps_until_gate(definition)] == ["only"]


def test_resuming_continues_after_the_released_gate():
    definition = PlaybookService().compile_playbook(_GATED_YAML)

    assert [s.id for s in steps_until_gate(definition, resume_after="gate")] == ["after"]


def test_resuming_after_an_unknown_step_is_an_error_not_a_silent_restart():
    """Failing loudly matters: the quiet alternative re-runs completed steps."""
    definition = PlaybookService().compile_playbook(_GATED_YAML)

    with pytest.raises(KeyError):
        steps_until_gate(definition, resume_after="no_such_step")


# --------------------------------------------------------------------------- #
# The endpoint: who may release the gate, and what happens when they do
# --------------------------------------------------------------------------- #


async def _seed_paused_run(db: AsyncSession, *, org_id: str = DEFAULT_ORG_ID) -> str:
    """A run parked exactly where the executor parks one."""
    playbook = PlaybookRow(
        id=generate_id("pb"),
        org_id=org_id,
        name="HITL Gated PB",
        description="",
        yaml_content=_GATED_YAML,
        trigger_type="manual",
        trigger_config={},
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    # Committed on its own: there is no ORM relationship between the two rows,
    # so SQLAlchemy cannot infer the insert order for the playbook_id FK.
    db.add(playbook)
    await db.commit()

    now = datetime.now(UTC)
    execution = PlaybookExecutionRow(
        id=generate_id("pbe"),
        org_id=org_id,
        playbook_id=playbook.id,
        status=PlaybookStatus.PAUSED_HITL.value,
        trigger_data={},
        step_results={
            "first": {
                "step_id": "first",
                "status": StepExecutionStatus.COMPLETED.value,
                "started_at": now.isoformat(),
                "completed_at": now.isoformat(),
                "output": {"stub": True},
                "error": None,
            },
            "gate": {
                "step_id": "gate",
                "status": StepExecutionStatus.RUNNING.value,
                "started_at": now.isoformat(),
                "completed_at": None,
                "output": {"awaiting_approval": True},
                "error": None,
            },
        },
        started_at=now,
    )
    db.add(execution)
    await db.commit()
    return execution.id


async def test_a_plain_analyst_cannot_release_the_gate(
    client: AsyncClient, db_session: AsyncSession, analyst_token: str, admin_token: str
):
    """The gate is only worth having if not everyone can open it."""
    execution_id = await _seed_paused_run(db_session)

    resp = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(analyst_token),
        json={"decision": "approve"},
    )
    assert resp.status_code == 403, resp.text

    still = await client.get(
        f"/api/v1/playbooks/executions/{execution_id}", headers=auth_header(admin_token)
    )
    assert still.json()["status"] == PlaybookStatus.PAUSED_HITL.value


async def test_approval_records_the_decision_on_the_gate_step(
    client: AsyncClient, db_session: AsyncSession, admin_token: str
):
    execution_id = await _seed_paused_run(db_session)

    resp = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(admin_token),
        json={"decision": "approve", "comment": "checked the host first"},
    )
    assert resp.status_code == 200, resp.text

    gate = resp.json()["step_results"]["gate"]
    assert gate["status"] == StepExecutionStatus.COMPLETED.value
    assert gate["output"]["approved"] is True
    assert gate["output"]["comment"] == "checked the host first"
    assert gate["output"]["approver_id"], "an approval with no approver is not an approval"
    assert gate["output"]["awaiting_approval"] is False


async def test_rejection_fails_the_run_and_leaves_the_rest_unrun(
    client: AsyncClient, db_session: AsyncSession, admin_token: str
):
    """A refused gate is terminal — it must not quietly continue."""
    execution_id = await _seed_paused_run(db_session)

    resp = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(admin_token),
        json={"decision": "reject", "comment": "not authorised"},
    )
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["status"] == PlaybookStatus.FAILED.value
    assert body["step_results"]["gate"]["status"] == StepExecutionStatus.REJECTED.value
    assert body["step_results"]["gate"]["output"]["approved"] is False
    assert "after" not in body["step_results"]


async def test_the_gate_cannot_be_released_twice(
    client: AsyncClient, db_session: AsyncSession, admin_token: str
):
    """A double-submit must 409 rather than resolve the gate a second time."""
    execution_id = await _seed_paused_run(db_session)

    first = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(admin_token),
        json={"decision": "approve"},
    )
    assert first.status_code == 200, first.text

    second = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(admin_token),
        json={"decision": "reject"},
    )
    assert second.status_code == 409, second.text

    # The first decision stands; the second did not overwrite it.
    detail = await client.get(
        f"/api/v1/playbooks/executions/{execution_id}", headers=auth_header(admin_token)
    )
    assert detail.json()["step_results"]["gate"]["output"]["approved"] is True


async def test_a_decision_on_an_unknown_run_is_a_404(client: AsyncClient, admin_token: str):
    """Consistent with the read path: absent, not forbidden."""
    resp = await client.post(
        "/api/v1/playbooks/executions/pbe_does_not_exist/approve",
        headers=auth_header(admin_token),
        json={"decision": "approve"},
    )
    assert resp.status_code == 404, resp.text


async def test_a_decision_on_another_orgs_run_is_a_404_not_a_403(
    client: AsyncClient, db_session: AsyncSession, admin_token: str, sample_org
):
    """Cross-tenant access must not disclose that the execution exists (#394)."""
    from btagent_backend.db.models import OrganizationRow

    # ``organizations.name`` is UNIQUE and other suites seed generic names, so
    # this must be specific enough not to collide when the whole suite runs —
    # it passed in isolation and failed in the full run on a plain "Other".
    other = OrganizationRow(
        id="org_hitl_other",
        name="HITL gate cross-tenant fixture",
        created_at=datetime.now(UTC),
    )
    db_session.add(other)
    await db_session.commit()

    execution_id = await _seed_paused_run(db_session, org_id="org_hitl_other")

    resp = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(admin_token),
        json={"decision": "approve"},
    )
    assert resp.status_code == 404, resp.text


async def test_the_decision_lands_on_the_audit_chain(
    client: AsyncClient, db_session: AsyncSession, admin_token: str
):
    """Releasing a gate is a human authorising automation — it must be logged."""
    execution_id = await _seed_paused_run(db_session)

    approved = await client.post(
        f"/api/v1/playbooks/executions/{execution_id}/approve",
        headers=auth_header(admin_token),
        json={"decision": "approve", "comment": "logged please"},
    )
    assert approved.status_code == 200, approved.text

    audit = await client.get(
        "/api/v1/audit/entries?page_size=100", headers=auth_header(admin_token)
    )
    assert audit.status_code == 200, audit.text

    matching = [
        entry
        for entry in audit.json()["items"]
        if entry["action"] == "playbook_hitl_approved" and execution_id in entry.get("resource", "")
    ]
    assert matching, "approving a HITL gate left no audit entry"
