"""API + service tests for the hunt triage store (#119).

Exercises the full vertical against the in-memory SQLite app: record →
cluster → suppress → promote, plus RBAC and org-scoping guards.
"""

from conftest import auth_header


def _finding_body(**overrides) -> dict:
    body = {
        "source": "hunt_pack",
        "domain": "sigma",
        "title": "Suspicious encoded PowerShell",
        "description": "powershell -enc ...",
        "severity": "high",
        "confidence": 0.7,
        "technique_ids": ["T1059.001"],
        "entities": [{"kind": "host", "value": "WS-001"}],
        "observables": [{"type": "process_name", "value": "powershell.exe"}],
        "evidence": {"rule": "enc_pwsh", "hash": "abc123"},
    }
    body.update(overrides)
    return body


async def test_record_finding_clusters_on_insert(client, analyst_token):
    resp = await client.post(
        "/api/v1/hunt/findings", json=_finding_body(), headers=auth_header(analyst_token)
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["state"] == "clustered"
    assert data["cluster_id"] is not None
    assert data["technique_ids"] == ["T1059.001"]


async def test_similar_findings_collapse_into_one_cluster(client, analyst_token):
    # Two findings, same shape, different host -> one cluster, finding_count 2.
    for host in ("WS-010", "WS-011"):
        body = _finding_body(entities=[{"kind": "host", "value": host}])
        r = await client.post(
            "/api/v1/hunt/findings", json=body, headers=auth_header(analyst_token)
        )
        assert r.status_code == 201, r.text

    inbox = await client.get("/api/v1/hunt/findings", headers=auth_header(analyst_token))
    assert inbox.status_code == 200, inbox.text
    payload = inbox.json()
    # exactly one cluster carries our two host findings
    matching = [c for c in payload["clusters"] if c["finding_count"] >= 2]
    assert matching, payload
    assert any("T1059.001" in c["technique_ids"] for c in matching)


async def test_suppress_requires_senior(client, analyst_token):
    rec = await client.post(
        "/api/v1/hunt/findings", json=_finding_body(), headers=auth_header(analyst_token)
    )
    fid = rec.json()["id"]
    supp = await client.post(
        f"/api/v1/hunt/findings/{fid}/suppress",
        json={
            "name": "known noise",
            "reason": "approved admin tooling",
            "match": {"source": "hunt_pack", "technique_ids": ["T1059.001"]},
        },
        headers=auth_header(analyst_token),
    )
    assert supp.status_code == 403, supp.text


async def test_suppress_hides_finding_from_inbox(client, analyst_token, admin_token):
    rec = await client.post(
        "/api/v1/hunt/findings",
        json=_finding_body(entities=[{"kind": "host", "value": "WS-SUP"}]),
        headers=auth_header(analyst_token),
    )
    fid = rec.json()["id"]

    supp = await client.post(
        f"/api/v1/hunt/findings/{fid}/suppress",
        json={
            "name": "known noise",
            "reason": "approved admin tooling",
            "match": {"entity_values": ["WS-SUP"]},
        },
        headers=auth_header(admin_token),
    )
    assert supp.status_code == 201, supp.text
    assert supp.json()["state"] == "active"
    assert supp.json()["match_count"] >= 1

    # The suppressed finding is now hidden from the default inbox.
    inbox = await client.get("/api/v1/hunt/findings", headers=auth_header(analyst_token))
    shown_ids = {f["id"] for f in inbox.json()["findings"]}
    assert fid not in shown_ids

    # ...but the finding itself reports suppressed state on direct fetch.
    detail = await client.get(f"/api/v1/hunt/findings/{fid}", headers=auth_header(analyst_token))
    assert detail.json()["state"] == "suppressed"
    assert detail.json()["suppressed_by"] is not None


async def test_overbroad_suppression_rejected(client, admin_token):
    resp = await client.post(
        "/api/v1/hunt/suppressions",
        json={
            "name": "match everything",
            "reason": "oops",
            "match": {},
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 409, resp.text
    assert "criteria" in resp.json()["detail"]


async def test_suppress_mismatch_rejected(client, analyst_token, admin_token):
    rec = await client.post(
        "/api/v1/hunt/findings", json=_finding_body(), headers=auth_header(analyst_token)
    )
    fid = rec.json()["id"]
    # match references a technique the finding doesn't have
    resp = await client.post(
        f"/api/v1/hunt/findings/{fid}/suppress",
        json={
            "name": "wrong",
            "reason": "pasted wrong criteria",
            "match": {"technique_ids": ["T9999"]},
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 400, resp.text


async def test_promote_creates_investigation(client, analyst_token, admin_token):
    rec = await client.post(
        "/api/v1/hunt/findings",
        json=_finding_body(entities=[{"kind": "host", "value": "WS-PROMOTE"}]),
        headers=auth_header(analyst_token),
    )
    fid = rec.json()["id"]

    promo = await client.post(
        "/api/v1/hunt/findings/promote",
        json={"finding_ids": [fid], "title": "Escalated PowerShell hunt"},
        headers=auth_header(admin_token),
    )
    assert promo.status_code == 201, promo.text
    inv_id = promo.json()["investigation_id"]
    assert inv_id.startswith("inv_")
    assert promo.json()["promoted_finding_ids"] == [fid]

    detail = await client.get(f"/api/v1/hunt/findings/{fid}", headers=auth_header(analyst_token))
    assert detail.json()["state"] == "promoted"
    assert detail.json()["investigation_id"] == inv_id


async def test_promote_requires_senior(client, analyst_token):
    rec = await client.post(
        "/api/v1/hunt/findings", json=_finding_body(), headers=auth_header(analyst_token)
    )
    fid = rec.json()["id"]
    promo = await client.post(
        "/api/v1/hunt/findings/promote",
        json={"finding_ids": [fid]},
        headers=auth_header(analyst_token),
    )
    assert promo.status_code == 403, promo.text


async def test_get_unknown_finding_404(client, analyst_token):
    resp = await client.get(
        "/api/v1/hunt/findings/hfnd_doesnotexist", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_findings_require_auth(client):
    resp = await client.get("/api/v1/hunt/findings")
    assert resp.status_code == 401
