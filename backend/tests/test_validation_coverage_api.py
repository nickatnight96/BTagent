"""API tests for the detection-coverage map route (#118 Phase C).

Exercises ``GET /api/v1/validation/coverage-map`` — the read-only, RBAC-gated
(``hunt:view``) endpoint that derives per-technique ``last_validated`` +
staleness from the existing ``detection_validation_runs`` history. A default
validation run (replay) exercises ``T1059.001``, so it should surface as a
freshly-validated (not stale) technique in the map.
"""

from conftest import auth_header


async def test_coverage_map_requires_auth(client):
    resp = await client.get("/api/v1/validation/coverage-map")
    assert resp.status_code in (401, 403)


async def test_coverage_map_after_run_lists_fresh_technique(client, analyst_token):
    # Replay run exercises the built-in scenarios (incl. T1059.001).
    created = await client.post("/api/v1/validation/runs", headers=auth_header(analyst_token))
    assert created.status_code == 201, created.text

    resp = await client.get("/api/v1/validation/coverage-map", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stale_days"] == 90
    assert body["only_stale"] is False
    assert body["total"] == len(body["items"])
    by = {e["technique_id"]: e for e in body["items"]}
    assert "T1059.001" in by
    entry = by["T1059.001"]
    # Just validated → fresh, with a recent timestamp.
    assert entry["stale"] is False
    assert entry["last_validated"] is not None
    assert entry["days_since_validated"] == 0


async def test_coverage_map_only_stale_filter(client, analyst_token):
    await client.post("/api/v1/validation/runs", headers=auth_header(analyst_token))
    resp = await client.get(
        "/api/v1/validation/coverage-map",
        params={"only_stale": "true"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["only_stale"] is True
    # Every returned entry is stale, and a just-validated technique is excluded.
    assert all(e["stale"] for e in body["items"])
    assert "T1059.001" not in {e["technique_id"] for e in body["items"]}


async def test_coverage_map_stale_days_param(client, analyst_token):
    await client.post("/api/v1/validation/runs", headers=auth_header(analyst_token))
    # A 0-day-ish horizon isn't allowed (ge=1); 1 day still keeps a same-day
    # validation fresh. Echo the param back.
    resp = await client.get(
        "/api/v1/validation/coverage-map",
        params={"stale_days": 1},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["stale_days"] == 1
