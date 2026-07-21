"""API tests for the detection-validation routes (#118).

Exercises ``POST /api/v1/validation/runs`` (replay default scenarios → persist →
return the coverage report) and ``GET /api/v1/validation/runs`` (history list),
against the in-memory app. The default scenario set is deterministic, so the
encoded-PowerShell scenario reliably fires the ``windows_baseline`` rule.
"""

from conftest import auth_header


async def test_create_run_persists_and_returns_report(client, analyst_token):
    resp = await client.post("/api/v1/validation/runs", headers=auth_header(analyst_token))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["run_id"].startswith("valrun_")
    assert data["packs"] == ["windows_baseline"]
    assert data["scenarios_run"] == 2
    assert data["total_techniques"] >= 1
    # The encoded-PowerShell scenario fires → some detection.
    assert data["detected_pct"] > 0
    assert data["coverage_by_technique"]
    techniques = {c["technique_id"] for c in data["coverage_by_technique"]}
    assert "T1059.001" in techniques


async def test_run_then_list_history(client, analyst_token):
    created = await client.post("/api/v1/validation/runs", headers=auth_header(analyst_token))
    assert created.status_code == 201, created.text
    created_id = created.json()["id"]

    listed = await client.get("/api/v1/validation/runs", headers=auth_header(analyst_token))
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["total"] >= 1
    assert created_id in {item["id"] for item in body["items"]}
    # The list view omits the heavy per-technique payload.
    assert "coverage_by_technique" not in body["items"][0]


async def test_create_run_requires_auth(client):
    resp = await client.post("/api/v1/validation/runs")
    assert resp.status_code in (401, 403)


async def test_list_runs_requires_auth(client):
    resp = await client.get("/api/v1/validation/runs")
    assert resp.status_code in (401, 403)
