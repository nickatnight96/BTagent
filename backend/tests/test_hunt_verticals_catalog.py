"""Tests for the findings-vertical catalog service + ``GET /hunt/verticals``.

Covers the read-only reflection of config into the manual-runnable hunt
verticals (email, deception, NDR) with their run routes + derived schedule
status:

* the catalog lists every vertical with a well-formed run route + domain;
* ``schedule_enabled`` tracks the mock-first derivation (on with mocks, off
  without);
* the API route surfaces the catalog and is RBAC-gated (``hunt:view``).
"""

from conftest import auth_header

from btagent_backend.config import get_settings
from btagent_backend.services import hunt_vertical_catalog as svc


def test_catalog_lists_every_vertical():
    catalog = svc.list_hunt_verticals()
    assert [v["name"] for v in catalog] == list(svc.VERTICAL_NAMES)
    by_name = {v["name"]: v for v in catalog}
    assert set(by_name) == {"email", "deception", "ndr", "agentic"}
    for name, v in by_name.items():
        assert v["run_route"] == f"/hunt/{name}/run"
        assert v["domain"] == name
        assert isinstance(v["scan_interval_hours"], int)
    # Scheduled verticals carry a positive cadence.
    for name in ("email", "deception", "ndr"):
        assert by_name[name]["scheduled"] is True
        assert by_name[name]["scan_interval_hours"] > 0
    # Agentic is manual-only: no cron, so never schedule-enabled and no cadence.
    assert by_name["agentic"]["scheduled"] is False
    assert by_name["agentic"]["schedule_enabled"] is False
    assert by_name["agentic"]["scan_interval_hours"] == 0
    # Email is the only windowed vertical (its run route takes a lookback/window).
    assert by_name["email"]["windowed"] is True
    assert by_name["deception"]["windowed"] is False
    assert by_name["ndr"]["windowed"] is False


def test_schedule_enabled_tracks_mock_derivation(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    get_settings.cache_clear()
    try:
        # Only scheduled verticals derive their gate from mocks; manual-only
        # ones (agentic) are always off.
        scheduled = [v for v in svc.list_hunt_verticals() if v["scheduled"]]
        assert scheduled
        assert all(v["schedule_enabled"] for v in scheduled)
    finally:
        get_settings.cache_clear()

    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        assert not any(v["schedule_enabled"] for v in svc.list_hunt_verticals())
    finally:
        get_settings.cache_clear()


# --- API ---


async def test_get_verticals_route(client, analyst_token):
    resp = await client.get("/api/v1/hunt/verticals", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    verticals = resp.json()["verticals"]
    assert {v["name"] for v in verticals} == {"email", "deception", "ndr", "agentic"}
    for v in verticals:
        assert v["run_route"] == f"/hunt/{v['name']}/run"
        assert isinstance(v["scheduled"], bool)
        assert isinstance(v["schedule_enabled"], bool)
        assert isinstance(v["scan_interval_hours"], int)


async def test_get_verticals_requires_auth(client):
    resp = await client.get("/api/v1/hunt/verticals")
    assert resp.status_code in (401, 403)
