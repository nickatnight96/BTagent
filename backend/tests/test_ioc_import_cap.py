"""Tests for the IOC import bulk-size cap (#391).

The STIX / CSV import endpoints build their IOC list from a free-form payload
and funnel it into ``create_iocs_bulk`` — the same insert path the ``POST
/iocs`` bulk route uses. That route caps its list via Pydantic
(``BulkCreateIOCRequest.iocs`` ``max_length=_MAX_BULK_IOCS``); the import paths
previously had no equivalent guard, so an oversized bundle bypassed the cap.
These tests assert the import endpoints now reject an over-cap batch with 413
while a within-cap batch still imports.
"""

from __future__ import annotations

import json

from conftest import auth_header

from btagent_backend.api.v1.iocs import _MAX_BULK_IOCS


async def _make_investigation(client, token) -> str:
    resp = await client.post(
        "/api/v1/investigations",
        headers=auth_header(token),
        json={
            "title": "Import Cap Test",
            "description": "seeded by test_ioc_import_cap",
            "severity": "medium",
        },
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()["id"]


async def test_csv_import_over_cap_is_rejected(client, analyst_token):
    inv_id = await _make_investigation(client, analyst_token)
    lines = "\n".join(f"ip,val-{i}" for i in range(_MAX_BULK_IOCS + 1))
    csv_data = "type,value\n" + lines

    resp = await client.post(
        "/api/v1/iocs/import/csv",
        headers=auth_header(analyst_token),
        json={"data": csv_data, "investigation_id": inv_id},
    )
    assert resp.status_code == 413, resp.text
    assert "maximum bulk size" in resp.json()["detail"]


async def test_csv_import_within_cap_succeeds(client, analyst_token):
    inv_id = await _make_investigation(client, analyst_token)
    lines = "\n".join(f"ip,ok-{i}" for i in range(5))
    csv_data = "type,value\n" + lines

    resp = await client.post(
        "/api/v1/iocs/import/csv",
        headers=auth_header(analyst_token),
        json={"data": csv_data, "investigation_id": inv_id},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported"] == 5


async def test_stix_text_import_over_cap_is_rejected(client, analyst_token):
    inv_id = await _make_investigation(client, analyst_token)
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": f"[ipv4-addr:value = '10.0.{i // 256}.{i % 256}']",
            }
            for i in range(_MAX_BULK_IOCS + 1)
        ],
    }

    resp = await client.post(
        "/api/v1/iocs/import/stix",
        headers=auth_header(analyst_token),
        json={"data": json.dumps(bundle), "investigation_id": inv_id},
    )
    assert resp.status_code == 413, resp.text
    assert str(_MAX_BULK_IOCS) in resp.json()["detail"]
