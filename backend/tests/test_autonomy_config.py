"""Tests for the autonomy surface (#418 slices 3+6).

``GET /api/v1/config/autonomy`` reports effective per-category levels
(shared defaults merged with the org's overrides); ``PUT`` replaces the
org's override set wholesale, rejecting containment categories outright so
the store can never even claim to loosen the code-enforced HITL gate.
"""

from btagent_shared.types.config import IntegrationAutonomy
from conftest import auth_header

URL = "/api/v1/config/autonomy"


async def test_autonomy_reports_effective_levels(client, analyst_token):
    resp = await client.get(URL, headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    by_key = {c["key"]: c for c in data["categories"]}
    # Drift lock: one entry per IntegrationAutonomy field.
    assert set(by_key) == set(IntegrationAutonomy.model_fields)

    # Telemetry defaults autonomous; containment manual and force-gated.
    assert by_key["siem_query"]["level"] == "L3"
    assert by_key["siem_query"]["hitl_forced"] is False
    assert by_key["siem_query"]["overridden"] is False
    for containment in ("host_isolation", "firewall_rule", "account_disable"):
        assert by_key[containment]["level"] == "L0", containment
        assert by_key[containment]["hitl_forced"] is True, containment

    assert set(data["levels"]) == {"L0", "L1", "L2", "L3", "L4"}
    assert data["editable"] is True


async def test_put_overrides_and_clear(client, admin_token):
    put = await client.put(
        URL,
        headers=auth_header(admin_token),
        json={"overrides": {"siem_query": "L1", "playbook_execution": "L0"}},
    )
    assert put.status_code == 200, put.text
    by_key = {c["key"]: c for c in put.json()["categories"]}
    assert by_key["siem_query"]["level"] == "L1"
    assert by_key["siem_query"]["overridden"] is True
    assert by_key["playbook_execution"]["level"] == "L0"
    # Untouched categories keep their defaults and are not marked overridden.
    assert by_key["edr_query"]["level"] == "L3"
    assert by_key["edr_query"]["overridden"] is False

    # GET reflects the stored overrides.
    got = await client.get(URL, headers=auth_header(admin_token))
    assert {c["key"]: c for c in got.json()["categories"]}["siem_query"]["level"] == "L1"

    # Empty set reverts to pure defaults.
    cleared = await client.put(URL, headers=auth_header(admin_token), json={"overrides": {}})
    assert cleared.status_code == 200
    by_key = {c["key"]: c for c in cleared.json()["categories"]}
    assert by_key["siem_query"]["level"] == "L3"
    assert by_key["siem_query"]["overridden"] is False


async def test_put_rejects_containment_unknown_and_bad_levels(client, admin_token):
    for bad_body in (
        {"overrides": {"host_isolation": "L3"}},  # containment: never configurable
        {"overrides": {"firewall_rule": "L0"}},  # containment even at the same level
        {"overrides": {"not_a_category": "L1"}},
        {"overrides": {"siem_query": "L9"}},
    ):
        resp = await client.put(URL, headers=auth_header(admin_token), json=bad_body)
        assert resp.status_code == 422, bad_body

    # A rejected write must not have persisted anything.
    got = await client.get(URL, headers=auth_header(admin_token))
    assert all(c["overridden"] is False for c in got.json()["categories"])


async def test_put_requires_admin(client, analyst_token):
    resp = await client.put(
        URL, headers=auth_header(analyst_token), json={"overrides": {"siem_query": "L1"}}
    )
    assert resp.status_code == 403


async def test_autonomy_requires_auth(client):
    assert (await client.get(URL)).status_code == 401
