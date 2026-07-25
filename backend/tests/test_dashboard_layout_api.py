"""Tests for the per-user dashboard-layout preference (EPIC-5 role-tuned views).

Covers the role-default resolution (analyst → All board; admin → HITL queue),
the save → read-back round trip, the sections validator ("investigations" is
always retained; duplicates collapse), reset via DELETE, and rejection of
unknown section keys.
"""

from conftest import auth_header

from btagent_backend.services.dashboard_layout import DashboardLayout, role_default_layout

URL = "/api/v1/config/dashboard-layout"


def test_role_defaults_are_tuned_per_role():
    assert role_default_layout("analyst").default_status_filter == ""
    assert role_default_layout("senior_analyst").default_status_filter == "running"
    assert role_default_layout("incident_commander").default_status_filter == "awaiting_hitl"
    assert role_default_layout("admin").default_status_filter == "awaiting_hitl"
    # Unknown/future roles fall back to the analyst view.
    assert role_default_layout("intern").default_status_filter == ""
    # Callers get a copy — mutating it must not poison the shared default.
    layout = role_default_layout("analyst")
    layout.sections.remove("handover")
    assert "handover" in role_default_layout("analyst").sections


def test_sections_validator_keeps_investigations_and_dedupes():
    layout = DashboardLayout(sections=["handover", "handover"])
    assert layout.sections == ["handover", "investigations"]


async def test_get_returns_role_default_when_never_saved(client, analyst_token):
    resp = await client.get(URL, headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["source"] == "role_default"
    assert data["role"] == "analyst"
    assert data["layout"]["sections"] == ["handover", "investigations"]
    assert data["layout"]["default_status_filter"] == ""


async def test_admin_role_default_preselects_hitl_queue(client, admin_token):
    resp = await client.get(URL, headers=auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["source"] == "role_default"
    assert data["layout"]["default_status_filter"] == "awaiting_hitl"


async def test_put_then_get_round_trips_customization(client, analyst_token):
    put = await client.put(
        URL,
        headers=auth_header(analyst_token),
        json={"sections": ["investigations"], "default_status_filter": "running"},
    )
    assert put.status_code == 200, put.text
    assert put.json()["source"] == "user"

    got = await client.get(URL, headers=auth_header(analyst_token))
    assert got.status_code == 200, got.text
    data = got.json()
    assert data["source"] == "user"
    assert data["layout"]["sections"] == ["investigations"]
    assert data["layout"]["default_status_filter"] == "running"

    # Second PUT updates in place (upsert, not duplicate-row insert).
    put2 = await client.put(
        URL,
        headers=auth_header(analyst_token),
        json={"sections": ["handover", "investigations"], "default_status_filter": ""},
    )
    assert put2.status_code == 200, put2.text
    got2 = await client.get(URL, headers=auth_header(analyst_token))
    assert got2.json()["layout"]["default_status_filter"] == ""


async def test_delete_resets_to_role_default(client, analyst_token):
    await client.put(
        URL,
        headers=auth_header(analyst_token),
        json={"sections": ["investigations"], "default_status_filter": "failed"},
    )
    reset = await client.delete(URL, headers=auth_header(analyst_token))
    assert reset.status_code == 200, reset.text
    assert reset.json()["source"] == "role_default"

    got = await client.get(URL, headers=auth_header(analyst_token))
    data = got.json()
    assert data["source"] == "role_default"
    assert data["layout"]["default_status_filter"] == ""
    # DELETE with nothing saved is a no-op, not an error.
    reset2 = await client.delete(URL, headers=auth_header(analyst_token))
    assert reset2.status_code == 200


async def test_put_rejects_unknown_section_and_bad_filter(client, analyst_token):
    resp = await client.put(
        URL,
        headers=auth_header(analyst_token),
        json={"sections": ["handover", "cryptominer"], "default_status_filter": ""},
    )
    assert resp.status_code == 422

    resp2 = await client.put(
        URL,
        headers=auth_header(analyst_token),
        json={"sections": ["investigations"], "default_status_filter": "DROP TABLE"},
    )
    assert resp2.status_code == 422


async def test_requires_auth(client):
    resp = await client.get(URL)
    assert resp.status_code == 401
