"""API tests for the shift-handover summary route (EPIC-5 UC-5.1, #108).

Seeds activity through the public APIs (an investigation + a hunt finding),
then asserts ``GET /api/v1/handover`` rolls both into the summary: the new
investigation appears with ``is_new``, the finding lands in the severity
buckets and the untriaged count, and the open-backlog rollup counts the case.
"""

from conftest import auth_header


async def _seed_activity(client, token) -> str:
    inv = await client.post(
        "/api/v1/investigations",
        headers=auth_header(token),
        json={
            "title": "Handover Test — Suspicious OAuth Grant",
            "description": "seeded by test_handover_api",
            "severity": "high",
        },
    )
    assert inv.status_code in (200, 201), inv.text
    inv_id = inv.json()["id"]

    finding = await client.post(
        "/api/v1/hunt/findings",
        headers=auth_header(token),
        json={
            "source": "identity",
            "domain": "identity",
            "title": "Handover Test — anomalous token grant",
            "description": "seeded by test_handover_api",
            "severity": "critical",
        },
    )
    assert finding.status_code == 201, finding.text
    return inv_id


async def test_handover_rolls_up_window_activity(client, analyst_token):
    inv_id = await _seed_activity(client, analyst_token)

    resp = await client.get("/api/v1/handover", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["window_hours"] == 8
    # The seeded investigation is in the window list and flagged new.
    by_id = {i["id"]: i for i in data["investigations"]}
    assert inv_id in by_id
    assert by_id[inv_id]["is_new"] is True
    assert by_id[inv_id]["severity"] == "high"

    # The seeded finding lands in the severity buckets and is untriaged.
    assert data["findings_by_severity"].get("critical", 0) >= 1
    assert data["findings_untriaged"] >= 1

    # The new case is still open, so it counts in the open backlog.
    assert data["open_by_severity"].get("high", 0) >= 1

    # Headline is the deterministic rollup sentence.
    assert "hunt finding(s)" in data["headline"]
    assert "still open" in data["headline"]


async def test_handover_window_param_validated(client, analyst_token):
    ok = await client.get("/api/v1/handover?window_hours=24", headers=auth_header(analyst_token))
    assert ok.status_code == 200
    assert ok.json()["window_hours"] == 24

    bad = await client.get("/api/v1/handover?window_hours=0", headers=auth_header(analyst_token))
    assert bad.status_code == 422


async def test_handover_requires_auth(client):
    resp = await client.get("/api/v1/handover")
    assert resp.status_code in (401, 403)
