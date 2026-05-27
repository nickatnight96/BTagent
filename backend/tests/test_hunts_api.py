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
