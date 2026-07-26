"""Tests for the read-only autonomy surface (#418 slice 3).

``GET /api/v1/config/autonomy`` reports the effective per-category
``IntegrationAutonomy`` levels: telemetry queries autonomous, containment
manual AND flagged ``hitl_forced`` (gated in code regardless of level), with
a level legend and ``editable: false`` until the editing slice lands.
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
    for containment in ("host_isolation", "firewall_rule", "account_disable"):
        assert by_key[containment]["level"] == "L0", containment
        assert by_key[containment]["hitl_forced"] is True, containment

    assert set(data["levels"]) == {"L0", "L1", "L2", "L3", "L4"}
    assert data["editable"] is False


async def test_autonomy_requires_auth(client):
    resp = await client.get(URL)
    assert resp.status_code == 401
