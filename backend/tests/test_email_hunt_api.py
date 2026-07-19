"""API tests for the email-hunt run route (email vertical, slice 5).

Exercises ``POST /hunt/email/run`` against the in-memory app: an analyst
triggers an email hunt over an explicit window, the mock connectors' findings
land in the triage inbox, and the new ``email`` domain filter surfaces them.
"""

from conftest import auth_header

# Wide window so every connector's mid-2026 fixtures fall inside it.
_WIDE = {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}


async def test_run_email_hunt_lands_findings(client, analyst_token):
    resp = await client.post(
        "/api/v1/hunt/email/run", json=_WIDE, headers=auth_header(analyst_token)
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["findings_created"] >= 1
    assert data["findings_emitted"] == data["findings_created"]
    assert sum(data["counts_by_severity"].values()) == data["findings_emitted"]
    assert data["window"]["start"] == _WIDE["start"]

    # The findings are queryable through the new email domain filter.
    inbox = await client.get(
        "/api/v1/hunt/findings?domain=email", headers=auth_header(analyst_token)
    )
    assert inbox.status_code == 200, inbox.text
    clusters = inbox.json()["clusters"]
    assert clusters


async def test_run_requires_auth(client):
    resp = await client.post("/api/v1/hunt/email/run", json=_WIDE)
    assert resp.status_code in (401, 403)


async def test_default_lookback_runs_cleanly(client, analyst_token):
    # No explicit window → derives one from lookback_hours; the run must
    # succeed and return a well-formed summary even if no recent mail matches.
    resp = await client.post(
        "/api/v1/hunt/email/run", json={"lookback_hours": 24}, headers=auth_header(analyst_token)
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert set(data) == {
        "window",
        "total_incidents",
        "active_incident_count",
        "findings_emitted",
        "findings_created",
        "counts_by_severity",
    }
    assert data["window"]["start"] and data["window"]["end"]


async def test_domain_filter_accepts_email(client, analyst_token):
    resp = await client.get(
        "/api/v1/hunt/findings?domain=email", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200, resp.text


async def test_bad_domain_filter_rejected(client, analyst_token):
    resp = await client.get(
        "/api/v1/hunt/findings?domain=not_a_domain", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 422
