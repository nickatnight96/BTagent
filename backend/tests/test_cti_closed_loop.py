"""Tests for the CTI → Detection closed loop (#113 Phase C).

Covers the three additions layered on the merged #468 / #118 pipeline:

* **Draft-edit path** — ``set_proposal_sigma`` flips a proposal to ``modified``,
  stores the analyst-edited body on ``final_sigma_yaml``, rejects a body that
  does not parse as a Sigma rule, and refuses editing a shipped / rejected row.
  The edited body is what the composer ships (``_shipped_yaml`` precedence).
* **pr_outcome tracking** — the composer stamps ``pr_opened``; ``record_pr_outcome``
  moves ``pr_opened -> merged`` / ``rejected`` (one-shot, PR-must-be-open guard).
* **Merge closed loop** — a ``merged`` outcome best-effort auto-installs the rule
  as a #112 hunt-pack entry AND triggers a #118 SANDBOX-gated detection-validation
  run for its technique; a hook failure never sinks the merge-outcome write.

Isolation: every test seeds a dedicated per-test org (``generate_id('org')``),
never ``DEFAULT_ORG_ID`` — the backend suite shares one session-scoped in-memory
SQLite where committed rows persist, so COUNT/ledger assertions must be scoped.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.detection_proposal import ProposalState, PROutcome
from btagent_shared.types.enums import AuditCategory
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services import cti_detection_service as svc
from btagent_backend.services.audit_trail import AuditTrail

_VALID_SIGMA = (
    "title: Edited rule\n"
    "logsource:\n  category: process_creation\n"
    "detection:\n  sel:\n    CommandLine|contains: mimikatz\n  condition: sel\n"
    "level: high\n"
)


@pytest_asyncio.fixture()
async def dedicated_org(db_session: AsyncSession) -> str:
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name=f"cl-{org_id}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return org_id


async def _new_row(
    db: AsyncSession,
    org_id: str,
    *,
    state: str = ProposalState.PROPOSED.value,
    pr_outcome: str = PROutcome.PROPOSED.value,
    pr_url: str | None = None,
    techniques: list[str] | None = None,
    final_sigma_yaml: str | None = None,
) -> DetectionProposalRow:
    now = datetime.now(UTC)
    row = DetectionProposalRow(
        id=generate_id("dprop"),
        org_id=org_id,
        proposal_id=f"dp_{generate_id('n')}",
        source_stix_id=f"indicator--{generate_id('n')}",
        title="Credential dumping via mimikatz",
        sigma_yaml="title: Draft\ndetection:\n  sel:\n    Image|endswith: x\n  condition: sel\n",
        final_sigma_yaml=final_sigma_yaml,
        technique_ids=techniques if techniques is not None else ["T1003.001"],
        confidence=0.8,
        state=state,
        pr_outcome=pr_outcome,
        pr_url=pr_url,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    return row


# --------------------------------------------------------------------------- #
# (A) Draft-edit path
# --------------------------------------------------------------------------- #


class TestSetProposalSigma:
    async def test_edit_marks_modified_and_stores_final(self, db_session, dedicated_org) -> None:
        row = await _new_row(db_session, dedicated_org)
        updated = await svc.set_proposal_sigma(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            sigma_yaml=_VALID_SIGMA,
            edited_by="usr_engineer",
            review_rationale="tuned the selection",
        )
        assert updated.state == ProposalState.MODIFIED.value
        assert updated.final_sigma_yaml is not None
        assert "mimikatz" in updated.final_sigma_yaml
        assert updated.reviewed_by == "usr_engineer"
        assert updated.review_rationale == "tuned the selection"
        # The draft is untouched — only the final overlay changed.
        assert updated.sigma_yaml.startswith("title: Draft")

    async def test_edit_rejects_unparseable_sigma(self, db_session, dedicated_org) -> None:
        row = await _new_row(db_session, dedicated_org)
        # Valid YAML, but not a Sigma rule (no 'detection' key) → refused.
        with pytest.raises(ValueError, match="does not parse"):
            await svc.set_proposal_sigma(
                db_session,
                org_id=dedicated_org,
                row_id=row.id,
                sigma_yaml="just: a\nplain: mapping\n",
            )
        # Also a body that is not even valid YAML.
        with pytest.raises(ValueError, match="does not parse"):
            await svc.set_proposal_sigma(
                db_session,
                org_id=dedicated_org,
                row_id=row.id,
                sigma_yaml="::: not : yaml : [",
            )
        # The row is unchanged — a rejected edit never mutates state.
        await db_session.refresh(row)
        assert row.state == ProposalState.PROPOSED.value
        assert row.final_sigma_yaml is None

    async def test_edit_refuses_shipped_row(self, db_session, dedicated_org) -> None:
        row = await _new_row(
            db_session,
            dedicated_org,
            state=ProposalState.ACCEPTED.value,
            pr_outcome=PROutcome.PR_OPENED.value,
            pr_url="https://git.example.com/detections/pull/1",
        )
        with pytest.raises(ValueError, match="already shipped"):
            await svc.set_proposal_sigma(
                db_session, org_id=dedicated_org, row_id=row.id, sigma_yaml=_VALID_SIGMA
            )

    async def test_edit_refuses_rejected_row(self, db_session, dedicated_org) -> None:
        row = await _new_row(db_session, dedicated_org, state=ProposalState.REJECTED.value)
        with pytest.raises(ValueError, match="cannot be edited"):
            await svc.set_proposal_sigma(
                db_session, org_id=dedicated_org, row_id=row.id, sigma_yaml=_VALID_SIGMA
            )

    async def test_edit_unknown_row_raises_lookup(self, db_session, dedicated_org) -> None:
        with pytest.raises(LookupError):
            await svc.set_proposal_sigma(
                db_session, org_id=dedicated_org, row_id="dprop_missing", sigma_yaml=_VALID_SIGMA
            )


class TestEditEndpoint:
    """The HTTP edit route over the shared client (DEFAULT_ORG_ID / analyst)."""

    async def _seed_proposed(self, db_session) -> str:
        from btagent_backend.db.models import DEFAULT_ORG_ID

        row = await _new_row(db_session, DEFAULT_ORG_ID)
        await db_session.commit()
        return row.id

    async def test_edit_endpoint_sets_modified(self, client, analyst_token, db_session) -> None:
        from conftest import auth_header

        row_id = await self._seed_proposed(db_session)
        resp = await client.post(
            f"/api/v1/cti/proposals/{row_id}/edit",
            json={"sigma_yaml": _VALID_SIGMA, "rationale": "sharper"},
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["state"] == "modified"
        assert body["final_sigma_yaml"] is not None
        assert "mimikatz" in body["final_sigma_yaml"]

    async def test_edit_endpoint_unparseable_is_422(
        self, client, analyst_token, db_session
    ) -> None:
        from conftest import auth_header

        row_id = await self._seed_proposed(db_session)
        resp = await client.post(
            f"/api/v1/cti/proposals/{row_id}/edit",
            json={"sigma_yaml": "just: a\nplain: mapping\n"},
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 422, resp.text

    async def test_edit_endpoint_unknown_is_404(self, client, analyst_token) -> None:
        from conftest import auth_header

        resp = await client.post(
            "/api/v1/cti/proposals/dprop_missing/edit",
            json={"sigma_yaml": _VALID_SIGMA},
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# (B) pr_outcome tracking + composer ships the edited body
# --------------------------------------------------------------------------- #


class TestComposerAndOutcome:
    async def test_compose_stamps_pr_opened(self, db_session, dedicated_org, monkeypatch) -> None:
        monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
        from btagent_agents.mcp.servers.git_mcp import MOCK_PR_LEDGER

        MOCK_PR_LEDGER.clear()
        row = await _new_row(db_session, dedicated_org, state=ProposalState.ACCEPTED.value)
        result = await svc.compose_detection_pr(db_session, org_id=dedicated_org, row_ids=[row.id])
        assert result["pr_url"].startswith("https://")
        await db_session.refresh(row)
        assert row.pr_outcome == PROutcome.PR_OPENED.value
        assert row.pr_url == result["pr_url"]

    async def test_compose_ships_edited_final_body(
        self, db_session, dedicated_org, monkeypatch
    ) -> None:
        """A ``modified`` row ships its ``final_sigma_yaml``, cited as edited."""
        monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
        from btagent_agents.mcp.servers.git_mcp import MOCK_PR_LEDGER

        MOCK_PR_LEDGER.clear()
        row = await _new_row(
            db_session,
            dedicated_org,
            state=ProposalState.MODIFIED.value,
            final_sigma_yaml=_VALID_SIGMA,
        )
        result = await svc.compose_detection_pr(db_session, org_id=dedicated_org, row_ids=[row.id])
        assert result["rule_count"] == 1
        shipped_files = MOCK_PR_LEDGER[-1]["files"]
        assert any("mimikatz" in f["content"] for f in shipped_files)

    async def test_compose_refuses_proposed_row(
        self, db_session, dedicated_org, monkeypatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
        row = await _new_row(db_session, dedicated_org, state=ProposalState.PROPOSED.value)
        with pytest.raises(ValueError, match="not eligible"):
            await svc.compose_detection_pr(db_session, org_id=dedicated_org, row_ids=[row.id])

    async def test_record_merge_requires_open_pr(self, db_session, dedicated_org) -> None:
        # A row that never shipped cannot be recorded as merged.
        row = await _new_row(
            db_session, dedicated_org, state=ProposalState.ACCEPTED.value
        )  # pr_outcome defaults to 'proposed'
        with pytest.raises(ValueError, match="PR is not open"):
            await svc.record_pr_outcome(
                db_session, org_id=dedicated_org, row_id=row.id, outcome=PROutcome.MERGED
            )

    async def test_record_outcome_rejects_nonrecordable(self, db_session, dedicated_org) -> None:
        row = await _new_row(db_session, dedicated_org, pr_outcome=PROutcome.PR_OPENED.value)
        with pytest.raises(ValueError, match="recordable"):
            await svc.record_pr_outcome(
                db_session, org_id=dedicated_org, row_id=row.id, outcome=PROutcome.PR_OPENED
            )

    async def test_record_reject_transition(self, db_session, dedicated_org) -> None:
        row = await _new_row(db_session, dedicated_org, pr_outcome=PROutcome.PR_OPENED.value)
        updated, closed_loop = await svc.record_pr_outcome(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            outcome=PROutcome.REJECTED,
            # rejection must not fire the merge closed loop:
            install_hunt_pack=_boom_installer,
            trigger_validation=_boom_validation,
        )
        assert updated.pr_outcome == PROutcome.REJECTED.value
        assert closed_loop == {}  # no closed loop on a non-merge outcome

    async def test_record_merge_is_one_shot(self, db_session, dedicated_org) -> None:
        row = await _new_row(db_session, dedicated_org, pr_outcome=PROutcome.PR_OPENED.value)
        await svc.record_pr_outcome(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            outcome=PROutcome.MERGED,
            install_hunt_pack=_noop_installer,
            trigger_validation=_noop_validation,
        )
        with pytest.raises(ValueError, match="PR is not open"):
            await svc.record_pr_outcome(
                db_session,
                org_id=dedicated_org,
                row_id=row.id,
                outcome=PROutcome.MERGED,
                install_hunt_pack=_noop_installer,
                trigger_validation=_noop_validation,
            )


# --------------------------------------------------------------------------- #
# (C) Merge closed loop — install + validation, best-effort
# --------------------------------------------------------------------------- #


class _InstallSpy:
    def __init__(self) -> None:
        self.calls: list[DetectionProposalRow] = []

    async def __call__(self, db: AsyncSession, row: DetectionProposalRow) -> dict:
        self.calls.append(row)
        return {"hunt_pack_run_id": "hrun_spy"}


class _ValidationSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, db: AsyncSession, actor_id: str, row: DetectionProposalRow) -> dict:
        self.calls.append((actor_id, (row.technique_ids or [None])[0]))
        return {"validation_triggered": True, "technique_id": (row.technique_ids or [None])[0]}


async def _noop_installer(db, row) -> dict:
    return {}


async def _noop_validation(db, actor_id, row) -> dict:
    return {"validation_triggered": True}


async def _boom_installer(db, row) -> dict:
    raise RuntimeError("install boom")


async def _boom_validation(db, actor_id, row) -> dict:
    raise RuntimeError("validation boom")


class TestMergeClosedLoop:
    async def test_merge_fires_both_hooks(self, db_session, dedicated_org) -> None:
        row = await _new_row(
            db_session,
            dedicated_org,
            pr_outcome=PROutcome.PR_OPENED.value,
            techniques=["T1059.001"],
        )
        install = _InstallSpy()
        validate = _ValidationSpy()
        updated, summary = await svc.record_pr_outcome(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            outcome=PROutcome.MERGED,
            actor_id="usr_senior",
            install_hunt_pack=install,
            trigger_validation=validate,
        )
        assert updated.pr_outcome == PROutcome.MERGED.value
        # Both closed-loop hooks fired exactly once, for this rule / technique.
        assert len(install.calls) == 1 and install.calls[0].id == row.id
        assert validate.calls == [("usr_senior", "T1059.001")]
        assert summary["hunt_pack_installed"] is True
        assert summary["validation_triggered"] is True

    async def test_merge_triggers_real_sandbox_validation_run(
        self, db_session, dedicated_org, monkeypatch
    ) -> None:
        """Default trigger genuinely creates a SANDBOX-gated validation run."""
        monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
        from btagent_agents.mcp.servers import atomic_red_team_mcp as art

        art.MOCK_ATOMIC_LEDGER.clear()
        art.MOCK_DETECTION_LEDGER.clear()

        row = await _new_row(
            db_session,
            dedicated_org,
            pr_outcome=PROutcome.PR_OPENED.value,
            techniques=["T1059.001"],
        )
        # Inject only the install spy (skip the pysigma engine run); use the REAL
        # default validation trigger so we exercise the sandbox gate + persist.
        _, summary = await svc.record_pr_outcome(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            outcome=PROutcome.MERGED,
            actor_id="usr_senior",
            install_hunt_pack=_InstallSpy(),
        )
        await db_session.commit()

        assert summary["validation_triggered"] is True
        # A validation RUN was created for this org, marked emulated + sandbox.
        runs = (
            (
                await db_session.execute(
                    select(DetectionValidationRunRow).where(
                        DetectionValidationRunRow.org_id == dedicated_org
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(runs) == 1
        assert runs[0].emulated is True
        assert runs[0].target_env == "sandbox"

        # And the run was sandbox-GATED: a DETECTION_VALIDATION trigger was
        # audited with target_env=sandbox before any emulator ran.
        audit_rows = await AuditTrail(db_session).get_entries(
            org_id=dedicated_org, category=AuditCategory.DETECTION_VALIDATION, limit=50
        )
        triggers = [r for r in audit_rows if r.action == "emulation_trigger"]
        assert triggers and triggers[0].details["target_env"] == "sandbox"

    async def test_merge_survives_hook_failures(self, db_session, dedicated_org) -> None:
        """Best-effort: both hooks blow up, the merge write still lands."""
        row = await _new_row(db_session, dedicated_org, pr_outcome=PROutcome.PR_OPENED.value)
        updated, summary = await svc.record_pr_outcome(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            outcome=PROutcome.MERGED,
            install_hunt_pack=_boom_installer,
            trigger_validation=_boom_validation,
        )
        assert updated.pr_outcome == PROutcome.MERGED.value
        assert summary["hunt_pack_installed"] is False
        assert summary["validation_triggered"] is False
        assert "install boom" in summary["hunt_pack_error"]
        assert "validation boom" in summary["validation_error"]

        # Durable across commit — a hook failure did not sink the merge write.
        await db_session.commit()
        fresh = (
            await db_session.execute(
                select(DetectionProposalRow).where(DetectionProposalRow.id == row.id)
            )
        ).scalar_one()
        await db_session.refresh(fresh)
        assert fresh.pr_outcome == PROutcome.MERGED.value

    async def test_default_installer_creates_pack_run(
        self, db_session, dedicated_org, monkeypatch
    ) -> None:
        """The real #112 install path runs the merged rule as an ad-hoc pack and
        records a HuntPackRunRow (mock connectors — nothing real fires)."""
        monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
        from btagent_backend.db.models_hunt import HuntPackRunRow
        from btagent_backend.services import hunt_pack_run_service

        sigma = (
            "title: Adhoc mimikatz\n"
            "logsource:\n  category: process_creation\n"
            "detection:\n  sel:\n    Image|endswith: \\mimikatz.exe\n  condition: sel\n"
            "level: high\n"
        )
        run_row = await hunt_pack_run_service.run_adhoc_rule_pack(
            db_session,
            org_id=dedicated_org,
            rule_id="cti-adhoc",
            title="Adhoc mimikatz",
            sigma_yaml=sigma,
            technique_ids=["T1003.001"],
        )
        assert run_row.org_id == dedicated_org
        assert run_row.pack_id.startswith("cti-merged-")
        found = (
            (
                await db_session.execute(
                    select(HuntPackRunRow).where(HuntPackRunRow.org_id == dedicated_org)
                )
            )
            .scalars()
            .all()
        )
        assert any(r.run_id == run_row.run_id for r in found)

    async def test_merge_no_technique_skips_validation_run(self, db_session, dedicated_org) -> None:
        """A rule with no technique installs but records no validation run."""
        row = await _new_row(
            db_session, dedicated_org, pr_outcome=PROutcome.PR_OPENED.value, techniques=[]
        )
        _, summary = await svc.record_pr_outcome(
            db_session,
            org_id=dedicated_org,
            row_id=row.id,
            outcome=PROutcome.MERGED,
            install_hunt_pack=_InstallSpy(),
        )
        await db_session.commit()
        assert summary["validation"]["validation_triggered"] is False
        count = (
            await db_session.execute(
                select(func.count())
                .select_from(DetectionValidationRunRow)
                .where(DetectionValidationRunRow.org_id == dedicated_org)
            )
        ).scalar_one()
        assert count == 0
