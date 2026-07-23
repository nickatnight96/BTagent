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
