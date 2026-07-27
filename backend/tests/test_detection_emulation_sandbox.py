"""SANDBOX-ENFORCEMENT tests for detection-validation emulation (#118).

This is the guardrail suite: it proves that a non-sandbox ``target_env`` is
REFUSED, that the refusal is written to the hash-chain audit ledger as a DENIED
row, and — the single most important assertion in the whole feature — that NO
emulator method is invoked on a denied target. It also proves the approved
(sandbox) path audits the trigger and dispatches the orchestrator, and that
everything is org-scoped.

Isolation: each COUNT/ledger assertion seeds and queries a dedicated per-test
org (``generate_id("org")``), never ``DEFAULT_ORG_ID`` — the backend suite
shares one session-scoped in-memory SQLite where committed rows persist.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.detection_validation import (
    CoverageDelta,
    EmulationRequest,
    Emulator,
    TargetEnv,
    TechniqueVerdict,
    ValidationVerdict,
)
from btagent_shared.types.enums import AuditCategory, AuditOutcome, Severity
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import OrganizationRow
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.detection_emulation_service import run_emulation_validation


@pytest_asyncio.fixture()
async def dedicated_org(db_session) -> str:
    """A fresh org row so ledger COUNT assertions are not polluted by other
    tests writing into the shared DEFAULT_ORG_ID."""
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name=f"emu-{org_id}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return org_id


class _Spy:
    """An orchestrator-run spy that records every call and returns a canned
    verdict. If the sandbox gate works, it is NEVER called on a denial."""

    def __init__(self) -> None:
        self.calls: list[EmulationRequest] = []

    async def __call__(self, request: EmulationRequest) -> TechniqueVerdict:
        self.calls.append(request)
        return TechniqueVerdict(
            technique_id=request.technique_id,
            verdict=ValidationVerdict.VALIDATED,
            emulator=request.emulator,
            expected_severity=request.expected_severity,
            observed_severity=request.expected_severity,
            latency_seconds=10.0,
            latency_sla_seconds=request.latency_sla_seconds,
            fired_rules=[],
            coverage_delta=CoverageDelta(technique_id=request.technique_id),
        )


async def _dv_rows(db_session, org_id: str) -> list:
    return await AuditTrail(db_session).get_entries(
        org_id=org_id, category=AuditCategory.DETECTION_VALIDATION, limit=100
    )


# --------------------------------------------------------------------------- #
# Denial path — the guardrail
# --------------------------------------------------------------------------- #


class TestNonSandboxIsRefusedAndAudited:
    async def test_production_target_denied_emulator_never_invoked(
        self, db_session, dedicated_org
    ) -> None:
        spy = _Spy()
        req = EmulationRequest(
            technique_id="T1059.001",
            target_env=TargetEnv.PRODUCTION,
            emulator=Emulator.ATOMIC_RED_TEAM,
        )
        outcome = await run_emulation_validation(
            db_session,
            actor_id="usr_commander",
            org_id=dedicated_org,
            request=req,
            orchestrator_run=spy,
        )
        # Refused with a 403 and NO verdict.
        assert outcome.approved is False
        assert outcome.http_status == 403
        assert outcome.outcome == AuditOutcome.DENIED.value
        assert outcome.verdict is None
        # The emulator/orchestrator was NEVER invoked.
        assert spy.calls == []
        # A DENIED audit row was written for this org, carrying the safety fields.
        await db_session.commit()
        rows = await _dv_rows(db_session, dedicated_org)
        assert len(rows) == 1
        row = rows[0]
        assert row.outcome == AuditOutcome.DENIED.value
        assert row.resource == "T1059.001"
        assert row.actor == "usr_commander"
        assert row.details["target_env"] == "production"
        assert outcome.audit_id == row.id


class TestOtherNonSandboxEnvs:
    @pytest.mark.parametrize(
        "env,label",
        [
            (TargetEnv.STAGING, "staging"),
            (TargetEnv.UNKNOWN, "unknown"),
        ],
    )
    async def test_staging_and_unknown_denied(self, db_session, dedicated_org, env, label) -> None:
        spy = _Spy()
        outcome = await run_emulation_validation(
            db_session,
            actor_id="usr_x",
            org_id=dedicated_org,
            request=EmulationRequest(technique_id="T1105", target_env=env),
            orchestrator_run=spy,
        )
        assert outcome.approved is False
        assert spy.calls == []
        await db_session.commit()
        rows = await _dv_rows(db_session, dedicated_org)
        assert len(rows) == 1
        assert rows[0].details["target_env"] == label
        assert rows[0].outcome == AuditOutcome.DENIED.value


# --------------------------------------------------------------------------- #
# Approved (sandbox) path
# --------------------------------------------------------------------------- #


class TestSandboxIsApprovedAuditedAndDispatched:
    async def test_sandbox_target_dispatches_and_audits_success(
        self, db_session, dedicated_org
    ) -> None:
        spy = _Spy()
        outcome = await run_emulation_validation(
            db_session,
            actor_id="usr_commander",
            org_id=dedicated_org,
            request=EmulationRequest(
                technique_id="T1059.001",
                target_env=TargetEnv.SANDBOX,
                expected_severity=Severity.HIGH,
            ),
            orchestrator_run=spy,
        )
        assert outcome.approved is True
        assert outcome.http_status == 201
        assert outcome.verdict is not None
        # The orchestrator was invoked exactly once.
        assert len(spy.calls) == 1
        assert spy.calls[0].technique_id == "T1059.001"
        # A SUCCESS trigger row was written for this org.
        await db_session.commit()
        rows = await _dv_rows(db_session, dedicated_org)
        assert len(rows) == 1
        assert rows[0].outcome == AuditOutcome.SUCCESS.value
        assert rows[0].details["target_env"] == "sandbox"

    async def test_default_orchestrator_runs_mock_end_to_end(
        self, db_session, dedicated_org
    ) -> None:
        """No injected spy: the real (mock-first) orchestrator runs end to end
        and produces a verdict without firing any real technique."""
        from btagent_agents.mcp.servers import atomic_red_team_mcp as art

        art.MOCK_ATOMIC_LEDGER.clear()
        art.MOCK_DETECTION_LEDGER.clear()

        outcome = await run_emulation_validation(
            db_session,
            actor_id="usr_commander",
            org_id=dedicated_org,
            request=EmulationRequest(
                technique_id="T1059.001",
                target_env=TargetEnv.SANDBOX,
                expected_severity=Severity.HIGH,
            ),
        )
        assert outcome.approved is True
        assert outcome.verdict is not None
        assert outcome.verdict.verdict == ValidationVerdict.VALIDATED
        # Assert mock: the run that happened executed nothing.
        assert art.MOCK_ATOMIC_LEDGER and art.MOCK_ATOMIC_LEDGER[0]["is_mock"] is True


# --------------------------------------------------------------------------- #
# Org scoping
# --------------------------------------------------------------------------- #


async def test_denials_are_org_scoped(db_session) -> None:
    """A denial audited for org A is invisible to org B's ledger read."""
    org_a = generate_id("org")
    org_b = generate_id("org")
    for oid in (org_a, org_b):
        db_session.add(OrganizationRow(id=oid, name=f"scope-{oid}", created_at=datetime.now(UTC)))
    await db_session.commit()

    await run_emulation_validation(
        db_session,
        actor_id="usr_a",
        org_id=org_a,
        request=EmulationRequest(technique_id="T1003", target_env=TargetEnv.PRODUCTION),
    )
    await db_session.commit()

    a_rows = await _dv_rows(db_session, org_a)
    b_rows = await _dv_rows(db_session, org_b)
    assert len(a_rows) == 1
    assert b_rows == []
