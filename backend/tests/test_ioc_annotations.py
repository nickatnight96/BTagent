"""API tests for IOC notebook annotations (#108 UC-5.2).

Exercises ``PATCH /api/v1/iocs/{id}/annotate``: pin/tags/note/disposition set
and partially updated (a pin toggle must not clobber tags or the note),
disposition restricted to the known vocabulary, and annotations surfaced on
the standard IOC read path.
"""

from conftest import auth_header


async def _seed_ioc(client, token) -> str:
    inv = await client.post(
        "/api/v1/investigations",
        headers=auth_header(token),
        json={
            "title": "Annotation Test — Phishing Wave",
            "description": "seeded by test_ioc_annotations",
            "severity": "medium",
        },
    )
    assert inv.status_code in (200, 201), inv.text

    ioc = await client.post(
        "/api/v1/iocs",
        headers=auth_header(token),
        json={
            "investigation_id": inv.json()["id"],
            "type": "domain",
            "value": "annotation-test.example.com",
        },
    )
    assert ioc.status_code == 201, ioc.text
    body = ioc.json()
    created = body[0] if isinstance(body, list) else body
    # New IOCs start un-annotated.
    assert created["pinned"] is False
    assert created["tags"] == []
    return created["id"]


async def test_annotate_and_partial_update(client, analyst_token):
    ioc_id = await _seed_ioc(client, analyst_token)

    full = await client.patch(
        f"/api/v1/iocs/{ioc_id}/annotate",
        headers=auth_header(analyst_token),
        json={
            "pinned": True,
            "tags": ["c2", "phishing"],
            "analyst_note": "Registered 7 days ago; resolves to known C2 block.",
            "disposition": "confirmed_malicious",
        },
    )
    assert full.status_code == 200, full.text
    data = full.json()
    assert data["pinned"] is True
    assert data["tags"] == ["c2", "phishing"]
    assert data["disposition"] == "confirmed_malicious"

    # Partial update: unpin only — tags/note/disposition must survive.
    partial = await client.patch(
        f"/api/v1/iocs/{ioc_id}/annotate",
        headers=auth_header(analyst_token),
        json={"pinned": False},
    )
    assert partial.status_code == 200, partial.text
    data = partial.json()
    assert data["pinned"] is False
    assert data["tags"] == ["c2", "phishing"]
    assert data["analyst_note"].startswith("Registered 7 days ago")
    assert data["disposition"] == "confirmed_malicious"

    # Annotations surface on the standard read path too.
    got = await client.get(f"/api/v1/iocs/{ioc_id}", headers=auth_header(analyst_token))
    assert got.status_code == 200
    assert got.json()["tags"] == ["c2", "phishing"]


async def test_annotate_validates_disposition_and_body(client, analyst_token):
    ioc_id = await _seed_ioc(client, analyst_token)

    bad_disposition = await client.patch(
        f"/api/v1/iocs/{ioc_id}/annotate",
        headers=auth_header(analyst_token),
        json={"disposition": "totally_fine_probably"},
    )
    assert bad_disposition.status_code == 422

    empty = await client.patch(
        f"/api/v1/iocs/{ioc_id}/annotate",
        headers=auth_header(analyst_token),
        json={},
    )
    assert empty.status_code == 400


async def test_annotate_requires_auth_and_existing_ioc(client, analyst_token):
    unauth = await client.patch("/api/v1/iocs/ioc_nope/annotate", json={"pinned": True})
    assert unauth.status_code in (401, 403)

    missing = await client.patch(
        "/api/v1/iocs/ioc_nope/annotate",
        headers=auth_header(analyst_token),
        json={"pinned": True},
    )
    assert missing.status_code == 404
