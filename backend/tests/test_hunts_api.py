"""Tests for the hunt-package endpoint (UC-2.2, #105) — vertical slice.

Exercises the first engine-backed route: a real HTTP request runs the
HuntPackageNode and returns a serialized HuntPackage. Confirms the
engine -> backend path works inside an actual request (not just pytest
on the node in isolation).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import auth_header

_ADVISORY = (
    "CISA advisory AA26-001: actor infrastructure includes 10.1.42.17 and "
    "evil-c2.example via hxxps://evil-c2[.]example/x. Hash "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
    "Exploited CVE-2026-12345."
)


@pytest.fixture(autouse=True)
def _mock_engine(monkeypatch):
    # The route runs the engine in mock mode (dev default), but make it
    # explicit so the test is hermetic regardless of ambient env.
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")


async def test_generate_hunt_package_happy_path(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": _ADVISORY, "source_label": "AA26-001", "backends": ["splunk", "sigma"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    pkg = resp.json()
    assert pkg["source_label"] == "AA26-001"
    assert pkg["extracted_ioc_count"] >= 4
    assert pkg["derived_techniques"]
    # 10.1.42.17 is in the correlation fixtures -> retro-hunt flags a sighting
    assert pkg["retro_report"]["compromise_suspected"] is True
    assert pkg["sigma_drafts"]
    assert pkg["mock_mode"] is True


async def test_hunt_package_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/hunts/package", json={"text": _ADVISORY})
    assert resp.status_code in (401, 403)


async def test_hunt_package_rejects_empty_text(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": ""},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 422  # min_length=1


async def test_clean_advisory_no_sighting(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": "Only indicator: 203.0.113.255 (not in our telemetry)."},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    pkg = resp.json()
    assert pkg["retro_report"]["compromise_suspected"] is False


# --- correlation workbench (UC-1.2) --------------------------------------- #


async def test_correlate_entity_returns_timeline(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/correlate",
        json={"entity_type": "ip", "entity_value": "10.1.42.17"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    tl = resp.json()
    # 10.1.42.17 correlates across >=3 sources in the fixtures
    assert len(tl["sources_queried"]) >= 3
    assert len(tl["events"]) >= 3
    assert tl["pivots"]
    assert len(tl["audit_trail"]) == len(tl["sources_queried"])


async def test_correlate_requires_auth(client: AsyncClient):
    resp = await client.post(
        "/api/v1/hunts/correlate",
        json={"entity_type": "ip", "entity_value": "10.1.42.17"},
    )
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Package persistence + history (#99 follow-through)
# --------------------------------------------------------------------------- #


async def test_generated_package_is_persisted_and_reopenable(
    client: AsyncClient, analyst_token: str
):
    """POST /hunts/package stores the artifact; the id round-trips via the
    history list, and the detail route returns the same package."""
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": _ADVISORY, "source_label": "persisted-advisory-probe"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    generated = resp.json()
    assert generated["id"], "generated package must carry the persisted id"

    listing = await client.get("/api/v1/hunts/packages", headers=auth_header(analyst_token))
    assert listing.status_code == 200, listing.text
    items = {i["id"]: i for i in listing.json()["items"]}
    assert generated["id"] in items
    summary = items[generated["id"]]
    assert summary["source_label"] == "persisted-advisory-probe"
    assert summary["extracted_ioc_count"] == generated["extracted_ioc_count"]
    assert summary["techniques"] == generated["derived_techniques"]

    detail = await client.get(
        f"/api/v1/hunts/packages/{generated['id']}", headers=auth_header(analyst_token)
    )
    assert detail.status_code == 200, detail.text
    reopened = detail.json()
    assert reopened["id"] == generated["id"]
    assert reopened["source_label"] == "persisted-advisory-probe"
    assert reopened["extracted_ioc_count"] == generated["extracted_ioc_count"]
    assert reopened["sigma_drafts"] == generated["sigma_drafts"]
    assert reopened["queries"] == generated["queries"]


async def test_package_detail_404_on_unknown_id(client: AsyncClient, analyst_token: str):
    resp = await client.get(
        "/api/v1/hunts/packages/hpkg_DOESNOTEXIST", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_package_history_requires_auth(client: AsyncClient):
    assert (await client.get("/api/v1/hunts/packages")).status_code in (401, 403)
    assert (await client.get("/api/v1/hunts/packages/hpkg_x")).status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Package → investigation promote (#99 payoff)
# --------------------------------------------------------------------------- #


async def _generate_package(client: AsyncClient, token: str, text: str, label: str) -> dict:
    resp = await client.post(
        "/api/v1/hunts/package",
        json={"text": text, "source_label": label},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_promote_package_opens_high_severity_case_on_sightings(
    client: AsyncClient, analyst_token: str
):
    """A package with historical sightings promotes to a HIGH investigation,
    the lineage round-trips through summary + detail, and the case is real."""
    pkg = await _generate_package(client, analyst_token, _ADVISORY, "promote-me")

    resp = await client.post(
        f"/api/v1/hunts/packages/{pkg['id']}/promote", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 201, resp.text
    promoted = resp.json()
    assert promoted["package_id"] == pkg["id"]
    assert promoted["severity"] == "high"  # _ADVISORY hits the sighting fixtures
    assert promoted["title"] == "Hunt: promote-me"
    inv_id = promoted["investigation_id"]

    # The investigation exists and carries the derived description.
    inv = await client.get(f"/api/v1/investigations/{inv_id}", headers=auth_header(analyst_token))
    assert inv.status_code == 200, inv.text
    assert pkg["id"] in inv.json()["description"]
    assert inv.json()["severity"] == "high"

    # Lineage is visible in the history list and the reopened package.
    listing = await client.get("/api/v1/hunts/packages", headers=auth_header(analyst_token))
    summary = {i["id"]: i for i in listing.json()["items"]}[pkg["id"]]
    assert summary["investigation_id"] == inv_id

    detail = await client.get(
        f"/api/v1/hunts/packages/{pkg['id']}", headers=auth_header(analyst_token)
    )
    assert detail.json()["investigation_id"] == inv_id


async def test_promote_clean_package_opens_medium_case(client: AsyncClient, analyst_token: str):
    pkg = await _generate_package(
        client, analyst_token, "Only indicator: 203.0.113.255 (not in our telemetry).", "clean"
    )
    resp = await client.post(
        f"/api/v1/hunts/packages/{pkg['id']}/promote", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["severity"] == "medium"


async def test_promote_twice_conflicts(client: AsyncClient, analyst_token: str):
    pkg = await _generate_package(client, analyst_token, _ADVISORY, "double-promote")
    first = await client.post(
        f"/api/v1/hunts/packages/{pkg['id']}/promote", headers=auth_header(analyst_token)
    )
    assert first.status_code == 201, first.text
    second = await client.post(
        f"/api/v1/hunts/packages/{pkg['id']}/promote", headers=auth_header(analyst_token)
    )
    assert second.status_code == 409
    assert first.json()["investigation_id"] in second.json()["detail"]


async def test_promote_unknown_package_404(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/packages/hpkg_DOESNOTEXIST/promote", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_promote_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/hunts/packages/hpkg_x/promote")
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Direct hunt planning (#99 Phase A) — POST /hunts/plan
# --------------------------------------------------------------------------- #


async def test_generate_hunt_plan_from_adversary(client: AsyncClient, analyst_token: str):
    """Naming an adversary yields a full runbook: hypotheses ordered by
    priority, per-TTP entries with per-backend queries, READY state."""
    resp = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    assert plan["id"].startswith("hunt_")
    assert plan["state"] == "ready"
    assert plan["input"]["adversaries"] == ["APT29"]
    assert plan["hypotheses"], "adversary input must produce hypotheses"
    assert plan["ttp_entries"], "hypotheses must expand into runbook entries"
    priorities = [h["priority"] for h in plan["hypotheses"]]
    assert priorities == sorted(priorities, reverse=True)
    # Default backend fan-out includes splunk; every entry carries queries.
    first = plan["ttp_entries"][0]
    assert "splunk" in first["queries"]
    assert first["state"] == "not_started"


async def test_generate_hunt_plan_from_ttps_pins_backends(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/plan",
        json={"ttps": ["T1059.001"], "backends": ["splunk"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    ttp_ids = {e["ttp_id"] for e in plan["ttp_entries"]}
    assert "T1059.001" in ttp_ids
    for entry in plan["ttp_entries"]:
        assert set(entry["queries"].keys()) <= {"splunk"}


async def test_hunt_plan_requires_a_target(client: AsyncClient, analyst_token: str):
    resp = await client.post("/api/v1/hunts/plan", json={}, headers=auth_header(analyst_token))
    assert resp.status_code == 422


async def test_hunt_plan_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/hunts/plan", json={"adversaries": ["APT29"]})
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Plan persistence + history (#99 follow-through)
# --------------------------------------------------------------------------- #


async def test_generated_plan_is_persisted_and_reopenable(client: AsyncClient, analyst_token: str):
    """POST /hunts/plan stores the plan under its own id; the history list
    summarizes it and the detail route returns the identical runbook."""
    resp = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"], "ttps": ["T1059.001"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()

    listing = await client.get("/api/v1/hunts/plans", headers=auth_header(analyst_token))
    assert listing.status_code == 200, listing.text
    items = {i["id"]: i for i in listing.json()["items"]}
    assert plan["id"] in items
    summary = items[plan["id"]]
    assert summary["status"] == "ready"
    assert summary["adversaries"] == ["APT29"]
    assert summary["ttps"] == ["T1059.001"]
    assert summary["hypothesis_count"] == len(plan["hypotheses"])
    assert summary["entry_count"] == len(plan["ttp_entries"])
    assert summary["from_proposal"] is False

    detail = await client.get(
        f"/api/v1/hunts/plans/{plan['id']}", headers=auth_header(analyst_token)
    )
    assert detail.status_code == 200, detail.text
    reopened = detail.json()
    assert reopened["id"] == plan["id"]
    assert reopened["hypotheses"] == plan["hypotheses"]
    assert reopened["ttp_entries"] == plan["ttp_entries"]


async def test_plan_detail_404_on_unknown_id(client: AsyncClient, analyst_token: str):
    resp = await client.get(
        "/api/v1/hunts/plans/hunt_DOESNOTEXIST", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_plan_history_requires_auth(client: AsyncClient):
    assert (await client.get("/api/v1/hunts/plans")).status_code in (401, 403)
    assert (await client.get("/api/v1/hunts/plans/hunt_x")).status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Direct-plan execution (#99 Phase B)
# --------------------------------------------------------------------------- #


async def test_execute_direct_plan_runs_inline_and_reopens(client: AsyncClient, analyst_token: str):
    """Mock-connector execution runs inline, records NULL-proposal history,
    and the executed plan still re-opens (last_run popped before validate)."""
    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan_id = gen.json()["id"]

    resp = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200, resp.text
    executed = resp.json()
    assert executed["plan_id"] == plan_id
    assert executed["queued"] is False
    assert isinstance(executed["findings_created"], int)

    # The executed plan re-opens despite the stored last_run summary.
    detail = await client.get(f"/api/v1/hunts/plans/{plan_id}", headers=auth_header(analyst_token))
    assert detail.status_code == 200, detail.text
    assert detail.json()["state"] == "completed"

    # Still listed, still ready for a re-execute.
    listing = await client.get("/api/v1/hunts/plans", headers=auth_header(analyst_token))
    summary = {i["id"]: i for i in listing.json()["items"]}[plan_id]
    assert summary["status"] == "ready"

    second = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert second.status_code == 200, second.text


async def test_execute_plan_404_on_unknown_id(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/hunts/plans/hunt_DOESNOTEXIST/execute", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_execute_plan_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/hunts/plans/hunt_x/execute")
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Plan run history surfacing (#99 follow-through)
# --------------------------------------------------------------------------- #


async def test_plan_run_history_and_last_run_summary(client: AsyncClient, analyst_token: str):
    """Executing a plan lands a run row in GET /hunts/plans/{id}/runs (with
    NULL proposal_id) and the history summary gains last_run_* fields."""
    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan_id = gen.json()["id"]

    # Before execution: empty run history, no last_run summary.
    runs = await client.get(
        f"/api/v1/hunts/plans/{plan_id}/runs", headers=auth_header(analyst_token)
    )
    assert runs.status_code == 200, runs.text
    assert runs.json() == {"items": [], "total": 0}

    listing = await client.get("/api/v1/hunts/plans", headers=auth_header(analyst_token))
    summary = {i["id"]: i for i in listing.json()["items"]}[plan_id]
    assert summary["last_run_findings"] is None
    assert summary["last_run_at"] is None

    execute = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert execute.status_code == 200, execute.text
    findings_created = execute.json()["findings_created"]

    # After execution: one run row, NULL proposal_id, matching counts.
    runs = await client.get(
        f"/api/v1/hunts/plans/{plan_id}/runs", headers=auth_header(analyst_token)
    )
    body = runs.json()
    assert body["total"] == 1
    run = body["items"][0]
    assert run["plan_row_id"] == plan_id
    assert run["proposal_id"] is None
    assert run["findings_created"] == findings_created
    assert run["status"] in ("completed", "completed_with_errors")
    assert run["started_at"]

    listing = await client.get("/api/v1/hunts/plans", headers=auth_header(analyst_token))
    summary = {i["id"]: i for i in listing.json()["items"]}[plan_id]
    assert summary["last_run_findings"] == findings_created
    assert summary["last_run_at"] is not None


async def test_plan_runs_404_on_unknown_plan(client: AsyncClient, analyst_token: str):
    resp = await client.get(
        "/api/v1/hunts/plans/hunt_DOESNOTEXIST/runs", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_plan_runs_require_auth(client: AsyncClient):
    resp = await client.get("/api/v1/hunts/plans/hunt_x/runs")
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Plan export (#99 Phase B)
# --------------------------------------------------------------------------- #


async def test_export_plan_markdown(client: AsyncClient, analyst_token: str):
    """Markdown export carries the runbook content and a download filename."""
    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"], "ttps": ["T1059.001"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan = gen.json()

    resp = await client.get(
        f"/api/v1/hunts/plans/{plan['id']}/export?format=md",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/markdown")
    assert f'filename="hunt_plan_{plan["id"]}.md"' in resp.headers["content-disposition"]
    md = resp.text
    assert "# Hunt Plan: APT29, T1059.001" in md
    assert "## Executive summary" in md
    assert "## Hypotheses (priority order)" in md
    # Every runbook entry appears with its queries fenced.
    for entry in plan["ttp_entries"]:
        assert f"## {entry['ttp_id']}" in md
    assert "```" in md
    assert "- [ ]" in md  # evidence checklist renders as task boxes


async def test_export_plan_pdf(client: AsyncClient, analyst_token: str):
    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan_id = gen.json()["id"]

    resp = await client.get(
        f"/api/v1/hunts/plans/{plan_id}/export?format=pdf",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:5] == b"%PDF-"


async def test_export_plan_404_and_auth(client: AsyncClient, analyst_token: str):
    resp = await client.get(
        "/api/v1/hunts/plans/hunt_DOESNOTEXIST/export", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404
    assert (await client.get("/api/v1/hunts/plans/hunt_x/export")).status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Hunt lesson → RAG on execution (#99 Phase C)
# --------------------------------------------------------------------------- #


async def test_execute_indexes_hunt_lesson(client: AsyncClient, analyst_token: str):
    """A completed execution lands a 'runbook' knowledge doc carrying the
    plan/run lineage and outcome."""
    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"adversaries": ["APT29"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan_id = gen.json()["id"]

    execute = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert execute.status_code == 200, execute.text
    findings_created = execute.json()["findings_created"]

    docs = await client.get("/api/v1/knowledge/documents", headers=auth_header(analyst_token))
    assert docs.status_code == 200, docs.text
    lessons = [
        d for d in docs.json()["items"] if (d.get("metadata") or {}).get("plan_id") == plan_id
    ]
    assert len(lessons) == 1, "exactly one lesson per execution"
    lesson = lessons[0]
    assert lesson["source_type"] == "runbook"
    assert lesson["metadata"]["kind"] == "hunt_lesson"
    assert lesson["metadata"]["run_id"].startswith("hrun_")
    expected_outcome = "hit" if findings_created else "clean"
    assert lesson["metadata"]["outcome"] == expected_outcome
    assert lesson["title"].startswith("Hunt lesson: APT29")


async def test_clean_ttps_file_detection_proposals(db_session):
    """Only clean TTPs (0 hits, 0 errors) file proposals; re-runs upsert
    instead of duplicating; analyst-decided rows are never overwritten."""
    from datetime import UTC, datetime

    from btagent_shared.types.hunt import Backend, HuntInput, HuntPlan, Query, TTPRunbookEntry
    from sqlalchemy import select

    from btagent_backend.db.models import DEFAULT_ORG_ID
    from btagent_backend.db.models_cti import DetectionProposalRow
    from btagent_backend.services.hunt_plan_service import _file_clean_ttp_proposals

    def entry(ttp_id: str, with_sigma: bool = False) -> TTPRunbookEntry:
        queries = (
            {Backend.SIGMA: Query(backend=Backend.SIGMA, query=f"title: {ttp_id} rule")}
            if with_sigma
            else {}
        )
        return TTPRunbookEntry(
            ttp_id=ttp_id,
            ttp_name=f"Technique {ttp_id}",
            rationale="test rationale",
            behavioral_description="suspicious behaviour",
            queries=queries,
        )

    plan = HuntPlan(
        id="hunt_TESTPROPOSE",
        org_id=DEFAULT_ORG_ID,
        input=HuntInput(ttps=["T1001", "T1002", "T1003"], initiated_by="usr_test"),
        ttp_entries=[entry("T1001", with_sigma=True), entry("T1002"), entry("T1003")],
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    summary = {
        "T1001": {"hits": 0, "errors": []},  # clean, has sigma query
        "T1002": {"hits": 3, "errors": []},  # hit — no proposal
        "T1003": {"hits": 0, "errors": ["boom"]},  # errored — no proposal
    }

    await _file_clean_ttp_proposals(
        db_session, plan=plan, org_id=DEFAULT_ORG_ID, ttp_summary=summary
    )
    rows = (
        (
            await db_session.execute(
                select(DetectionProposalRow).where(
                    DetectionProposalRow.source_stix_id.like("hunt-plan--hunt_TESTPROPOSE--%")
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.source_stix_id == "hunt-plan--hunt_TESTPROPOSE--T1001"
    assert row.technique_ids == ["T1001"]
    assert row.state == "proposed"
    assert row.sigma_yaml == "title: T1001 rule"  # runbook sigma preferred
    assert "clean" in row.rationale

    # Re-run: upsert, not duplicate.
    await _file_clean_ttp_proposals(
        db_session, plan=plan, org_id=DEFAULT_ORG_ID, ttp_summary=summary
    )
    rows = (
        (
            await db_session.execute(
                select(DetectionProposalRow).where(
                    DetectionProposalRow.source_stix_id.like("hunt-plan--hunt_TESTPROPOSE--%")
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1

    # An analyst decision survives re-execution.
    rows[0].state = "accepted"
    await db_session.flush()
    await _file_clean_ttp_proposals(
        db_session, plan=plan, org_id=DEFAULT_ORG_ID, ttp_summary=summary
    )
    refreshed = (
        await db_session.execute(
            select(DetectionProposalRow).where(
                DetectionProposalRow.source_stix_id == "hunt-plan--hunt_TESTPROPOSE--T1001"
            )
        )
    ).scalar_one()
    assert refreshed.state == "accepted"


async def test_skeleton_sigma_when_runbook_has_no_sigma_query(db_session):
    """Entries without a Sigma query get a reviewable skeleton draft."""
    from datetime import UTC, datetime

    from btagent_shared.types.hunt import HuntInput, HuntPlan, TTPRunbookEntry
    from sqlalchemy import select

    from btagent_backend.db.models import DEFAULT_ORG_ID
    from btagent_backend.db.models_cti import DetectionProposalRow
    from btagent_backend.services.hunt_plan_service import _file_clean_ttp_proposals

    plan = HuntPlan(
        id="hunt_TESTSKEL",
        org_id=DEFAULT_ORG_ID,
        input=HuntInput(ttps=["T1059.001"], initiated_by="usr_test"),
        ttp_entries=[
            TTPRunbookEntry(
                ttp_id="T1059.001",
                ttp_name="PowerShell",
                rationale="r",
                behavioral_description="encoded powershell",
            )
        ],
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await _file_clean_ttp_proposals(
        db_session,
        plan=plan,
        org_id=DEFAULT_ORG_ID,
        ttp_summary={"T1059.001": {"hits": 0, "errors": []}},
    )
    row = (
        await db_session.execute(
            select(DetectionProposalRow).where(
                DetectionProposalRow.source_stix_id == "hunt-plan--hunt_TESTSKEL--T1059.001"
            )
        )
    ).scalar_one()
    assert "status: experimental" in row.sigma_yaml
    assert "attack.t1059_001" in row.sigma_yaml
    assert "TODO(detection-engineering)" in row.sigma_yaml
    assert row.confidence == 0.3


async def test_execution_stamps_technique_exercises(client: AsyncClient, analyst_token: str):
    """Executing a plan upserts (org, technique) exercise rows with lineage;
    re-executions bump the count instead of duplicating."""
    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"ttps": ["T1059.001"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan = gen.json()
    plan_id = plan["id"]
    hunted_ttps = {e["ttp_id"] for e in plan["ttp_entries"]}

    execute = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert execute.status_code == 200, execute.text

    resp = await client.get("/api/v1/mitre/exercises", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    by_ttp = {i["technique_id"]: i for i in resp.json()["items"]}
    for ttp_id in hunted_ttps:
        assert ttp_id in by_ttp, f"{ttp_id} not stamped"
        row = by_ttp[ttp_id]
        assert row["last_plan_id"] == plan_id
        assert row["last_run_id"].startswith("hrun_")
        assert row["last_outcome"] in ("hit", "clean", "errored")
        assert row["exercise_count"] >= 1
    first_count = by_ttp[next(iter(hunted_ttps))]["exercise_count"]

    # Re-execute: same rows, bumped count.
    second = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert second.status_code == 200, second.text
    resp = await client.get("/api/v1/mitre/exercises", headers=auth_header(analyst_token))
    by_ttp_after = {i["technique_id"]: i for i in resp.json()["items"]}
    sample = next(iter(hunted_ttps))
    assert by_ttp_after[sample]["exercise_count"] == first_count + 1

    # Everything just ran — the stale filter must exclude it all.
    stale = await client.get(
        "/api/v1/mitre/exercises?older_than_days=90", headers=auth_header(analyst_token)
    )
    assert stale.status_code == 200
    stale_ttps = {i["technique_id"] for i in stale.json()["items"]}
    assert not (hunted_ttps & stale_ttps)


async def test_technique_exercises_require_auth(client: AsyncClient):
    resp = await client.get("/api/v1/mitre/exercises")
    assert resp.status_code in (401, 403)


async def test_exercise_gaps_list_never_exercised(
    client: AsyncClient, analyst_token: str, db_session
):
    """Gaps = corpus minus exercised set, org-scoped, with tactic filter."""
    from datetime import UTC, datetime

    from sqlalchemy import delete

    from btagent_backend.db.models import DEFAULT_ORG_ID
    from btagent_backend.db.models_mitre import MitreTechniqueRow, TechniqueExerciseRow

    # Test-only corpus rows (T99xx ids never collide with real ATT&CK data).
    db_session.add(MitreTechniqueRow(id="T9901", name="Exercised Tech", tactic="execution"))
    db_session.add(MitreTechniqueRow(id="T9902", name="Unexercised Tech", tactic="execution"))
    db_session.add(MitreTechniqueRow(id="T9903", name="Other Tactic Tech", tactic="persistence"))
    db_session.add(
        TechniqueExerciseRow(
            org_id=DEFAULT_ORG_ID,
            technique_id="T9901",
            last_exercised_at=datetime.now(UTC),
            last_plan_id="hunt_gapstest",
            last_run_id="hrun_gapstest",
            last_outcome="clean",
            exercise_count=1,
        )
    )
    await db_session.commit()
    try:
        resp = await client.get(
            "/api/v1/mitre/exercises/gaps?page_size=1000", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 200, resp.text
        ids = {i["technique_id"] for i in resp.json()["items"]}
        assert "T9902" in ids
        assert "T9903" in ids
        assert "T9901" not in ids  # exercised → not a gap

        filtered = await client.get(
            "/api/v1/mitre/exercises/gaps?tactic=persistence&page_size=1000",
            headers=auth_header(analyst_token),
        )
        f_ids = {i["technique_id"] for i in filtered.json()["items"]}
        assert "T9903" in f_ids
        assert "T9902" not in f_ids

        assert (await client.get("/api/v1/mitre/exercises/gaps")).status_code in (401, 403)
    finally:
        await db_session.execute(
            delete(TechniqueExerciseRow).where(
                TechniqueExerciseRow.technique_id.in_(["T9901", "T9902", "T9903"])
            )
        )
        await db_session.execute(
            delete(MitreTechniqueRow).where(MitreTechniqueRow.id.in_(["T9901", "T9902", "T9903"]))
        )
        await db_session.commit()


async def test_lesson_failure_never_sinks_execution(
    client: AsyncClient, analyst_token: str, monkeypatch
):
    """If knowledge indexing blows up, the execution still succeeds."""
    from btagent_backend.services.knowledge_service import KnowledgeService

    async def _boom(self, db, **kwargs):  # noqa: ANN001, ANN003
        raise RuntimeError("embedding backend down")

    monkeypatch.setattr(KnowledgeService, "ingest_document", _boom)

    gen = await client.post(
        "/api/v1/hunts/plan",
        json={"ttps": ["T1059.001"]},
        headers=auth_header(analyst_token),
    )
    assert gen.status_code == 200, gen.text
    plan_id = gen.json()["id"]

    execute = await client.post(
        f"/api/v1/hunts/plans/{plan_id}/execute", headers=auth_header(analyst_token)
    )
    assert execute.status_code == 200, execute.text
    assert isinstance(execute.json()["findings_created"], int)
