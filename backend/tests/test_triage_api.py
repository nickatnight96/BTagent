"""Tests for the alert-triage API (EPIC-3 UC-3.1)."""

from __future__ import annotations

from httpx import AsyncClient

from tests.helpers import auth_header


async def test_triage_requires_auth(client: AsyncClient):
    resp = await client.post("/api/v1/triage", json={"title": "x"})
    assert resp.status_code in (401, 403)


async def test_triage_malware_alert(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/triage",
        json={
            "title": "Ransomware payload quarantined on WS-12",
            "source": "crowdstrike",
            "severity": "low",
            "entities": {"host": ["WS-12"]},
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    r = resp.json()
    assert r["typed_intent"] == "malware_detected"
    assert r["proposed_severity"] == "critical"  # escalated from low
    assert r["severity_escalated"] is True
    assert r["disposition"] == "escalate"
    assert 2 <= len(r["next_steps"]) <= 3
    assert r["evidence"]
    assert 0.0 <= r["confidence"] <= 1.0


async def test_triage_benign_alert(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/triage",
        json={"title": "Known-good approved change window"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    r = resp.json()
    assert r["typed_intent"] == "benign"
    assert r["disposition"] == "close_benign"


async def test_triage_validates_empty_title(client: AsyncClient, analyst_token: str):
    resp = await client.post(
        "/api/v1/triage", json={"title": ""}, headers=auth_header(analyst_token)
    )
    assert resp.status_code == 422
