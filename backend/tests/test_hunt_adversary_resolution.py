"""Tests for #99 hunt-planning increments A + B.

A. Real adversary -> TTP resolution: ``build_adversary_ttp_resolver`` resolves a
   named actor against the seeded ``mitre_groups`` table, and the compiler
   injects it so "Hunt for APT29" pulls that group's *real* technique set
   (displacing the built-in stock fallback).
B. ``coverage_delta``: the compiler cross-references the org's deployed
   detections so ``ExecSummary.coverage_delta`` is populated (ttp -> already
   covered).

Deterministic under ``BTAGENT_MOCK_LLM=true``. All seeds go through the
rollback-per-test ``db_session`` and use existence-guarded / dedicated-org
inserts so they never collide with the shared session DB.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.types.hunt import HuntInput
from btagent_shared.utils.ids import generate_id
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_mitre import MitreGroupRow, MitreTechniqueRow
from btagent_backend.services.cti_detection_service import get_deployed_technique_ids
from btagent_backend.services.mitre_service import build_adversary_ttp_resolver
from btagent_backend.services.proposal_huntplan import compile_huntinput_to_huntplan


@pytest.fixture(autouse=True)
def _force_mock_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")


async def _seed_group(
    db: AsyncSession,
    *,
    gid: str,
    name: str,
    aliases: list[str],
    technique_ids: list[str],
) -> None:
    if await db.get(MitreGroupRow, gid) is None:
        db.add(
            MitreGroupRow(
                id=gid,
                name=name,
                aliases=aliases,
                description=f"{name} (test)",
                technique_ids=technique_ids,
            )
        )
    await db.flush()


async def _seed_technique(db: AsyncSession, *, tid: str, name: str, tactic: str) -> None:
    if await db.get(MitreTechniqueRow, tid) is None:
        db.add(MitreTechniqueRow(id=tid, name=name, tactic=tactic))
    await db.flush()


# --------------------------------------------------------------------------- #
# A. Resolver
# --------------------------------------------------------------------------- #


async def test_resolver_resolves_group_by_name(db_session: AsyncSession) -> None:
    await _seed_group(
        db_session,
        gid="G0016",
        name="APT29",
        aliases=["Cozy Bear", "The Dukes"],
        technique_ids=["T1071.001", "T1567.002"],
    )
    await _seed_technique(
        db_session, tid="T1071.001", name="Web Protocols", tactic="command-and-control"
    )

    resolver = await build_adversary_ttp_resolver(db_session, ["APT29"])
    assert resolver is not None
    resolved = resolver("APT29")
    assert resolved is not None
    assert {tid for tid, _ in resolved} == {"T1071.001", "T1567.002"}
    # Technique name is resolved from mitre_techniques where present; falls
    # back to the id when the corpus doesn't carry it.
    by_id = dict(resolved)
    assert by_id["T1071.001"] == "Web Protocols"
    assert by_id["T1567.002"] == "T1567.002"


async def test_resolver_matches_alias_case_insensitive(db_session: AsyncSession) -> None:
    await _seed_group(
        db_session,
        gid="G0016",
        name="APT29",
        aliases=["Cozy Bear"],
        technique_ids=["T1071.001"],
    )
    resolver = await build_adversary_ttp_resolver(db_session, ["cozy bear"])
    assert resolver is not None
    assert resolver("cozy bear") == [("T1071.001", "T1071.001")]


async def test_resolver_none_when_no_group_matches(db_session: AsyncSession) -> None:
    resolver = await build_adversary_ttp_resolver(db_session, ["NoSuchActor_zzz"])
    assert resolver is None


async def test_resolver_none_for_empty_adversaries(db_session: AsyncSession) -> None:
    assert await build_adversary_ttp_resolver(db_session, []) is None


async def test_compile_uses_resolved_group_techniques(db_session: AsyncSession) -> None:
    """End-to-end: compiling a hunt for APT29 with the DB-backed resolver
    yields the group's real technique set, not the stock fallback."""
    await _seed_group(
        db_session,
        gid="G0016",
        name="APT29",
        aliases=[],
        technique_ids=["T1071.001", "T1567.002"],
    )
    resolver = await build_adversary_ttp_resolver(db_session, ["APT29"])
    hunt_input = HuntInput(adversaries=["APT29"], initiated_by="usr_test")

    plan = await compile_huntinput_to_huntplan(
        hunt_input,
        org_id="org_res_test",
        adversary_resolver=resolver,
    )
    ttps = {h.ttp_id for h in plan.hypotheses}
    assert {"T1071.001", "T1567.002"} <= ttps
    # The built-in stock APT29 set (T1059.001 / T1078.004 / T1566.001) is
    # displaced by the resolved real set.
    assert "T1059.001" not in ttps
    apt = next(h for h in plan.hypotheses if h.ttp_id == "T1071.001")
    assert "mitre_group:APT29" in apt.sources


async def test_compile_without_resolver_uses_stock(db_session: AsyncSession) -> None:
    """No resolver injected -> the node's stock fallback still works."""
    hunt_input = HuntInput(adversaries=["APT29"], initiated_by="usr_test")
    plan = await compile_huntinput_to_huntplan(hunt_input, org_id="org_res_test")
    ttps = {h.ttp_id for h in plan.hypotheses}
    assert {"T1059.001", "T1078.004", "T1566.001"} <= ttps


# --------------------------------------------------------------------------- #
# B. coverage_delta
# --------------------------------------------------------------------------- #


def _proposal_row(org_id: str, *, tids: list[str], state: str) -> DetectionProposalRow:
    now = datetime.now(UTC)
    uid = generate_id("dprop")
    return DetectionProposalRow(
        id=uid,
        org_id=org_id,
        proposal_id=uid,
        source_stix_id=f"stix--{uid}",
        title=f"det {tids} ({state})",
        sigma_yaml="title: t\ndetection:\n  sel: {}\n  condition: sel\n",
        technique_ids=tids,
        state=state,
        created_at=now,
        updated_at=now,
    )


async def test_deployed_technique_ids_only_counts_deployed(db_session: AsyncSession) -> None:
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name="cov org", created_at=datetime.now(UTC)))
    await db_session.flush()

    db_session.add(_proposal_row(org_id, tids=["T1071.001"], state="accepted"))  # deployed
    db_session.add(_proposal_row(org_id, tids=["T1547.001"], state="proposed"))  # not deployed
    # Shipped (pr_url set) counts as deployed even if state isn't accepted.
    shipped = _proposal_row(org_id, tids=["T1003"], state="modified")
    shipped.pr_url = "https://git.example/detections/pull/7"
    db_session.add(shipped)
    await db_session.flush()

    deployed = await get_deployed_technique_ids(db_session, org_id=org_id)
    assert deployed == {"T1071.001", "T1003"}


async def test_coverage_delta_populated_from_deployed_detections(
    db_session: AsyncSession,
) -> None:
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name="cov org2", created_at=datetime.now(UTC)))
    await db_session.flush()
    db_session.add(_proposal_row(org_id, tids=["T1071.001"], state="accepted"))
    await db_session.flush()

    deployed = await get_deployed_technique_ids(db_session, org_id=org_id)
    hunt_input = HuntInput(ttps=["T1071.001", "T1059.001"], initiated_by="usr_test")
    plan = await compile_huntinput_to_huntplan(
        hunt_input,
        org_id=org_id,
        deployed_technique_ids=deployed,
    )

    cov = plan.executive_summary.coverage_delta
    # Every hypothesised technique gets a delta entry; the deployed one is True.
    assert cov["T1071.001"] is True
    assert cov["T1059.001"] is False


async def test_coverage_delta_empty_when_no_deployed_set(db_session: AsyncSession) -> None:
    """Passing no deployed set (the DB-free path) leaves the delta empty —
    the prior behaviour is preserved for pure unit compiles."""
    hunt_input = HuntInput(ttps=["T1071.001"], initiated_by="usr_test")
    plan = await compile_huntinput_to_huntplan(hunt_input, org_id="org_cov_none")
    assert plan.executive_summary.coverage_delta == {}
