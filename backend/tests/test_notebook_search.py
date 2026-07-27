"""API tests for cross-case notebook search (#108 UC-5.2).

``GET /api/v1/iocs/notebook/search`` surfaces analyst-annotated IOCs across
investigations: only annotated rows appear, ``q`` matches the note/tags as
well as the value, pinned rows order first, disposition filters exactly, and
AUTH-B1 scoping hides other analysts' cases from plain-analyst callers.
"""

from btagent_shared.types.enums import InvestigationStatus
from conftest import auth_header

from btagent_backend.db.models import InvestigationRow

URL = "/api/v1/iocs/notebook/search"


async def _seed_case(client, token, title: str) -> str:
    inv = await client.post(
        "/api/v1/investigations",
        headers=auth_header(token),
        json={"title": title, "description": "seeded by test_notebook_search", "severity": "low"},
    )
    assert inv.status_code in (200, 201), inv.text
    return inv.json()["id"]


async def _seed_ioc(client, token, investigation_id: str, value: str, annotate: dict | None):
    ioc = await client.post(
        "/api/v1/iocs",
        headers=auth_header(token),
        json={"investigation_id": investigation_id, "type": "domain", "value": value},
    )
    assert ioc.status_code == 201, ioc.text
    body = ioc.json()
    created = body[0] if isinstance(body, list) else body
    if annotate is not None:
        patched = await client.patch(
            f"/api/v1/iocs/{created['id']}/annotate",
            headers=auth_header(token),
            json=annotate,
        )
        assert patched.status_code == 200, patched.text
    return created["id"]


async def _seed_notebook(client, token) -> dict[str, str]:
    """Two cases with annotated IOCs + one bare IOC. Returns ids by key."""
    case_a = await _seed_case(client, token, "Notebook Search — Case A")
    case_b = await _seed_case(client, token, "Notebook Search — Case B")

    noted = await _seed_ioc(
        client,
        token,
        case_a,
        "beacon.example.com",
        {"analyst_note": "Cobalt Strike beacon staging domain", "disposition": "under_review"},
    )
    tagged_pinned = await _seed_ioc(
        client,
        token,
        case_b,
        "drop.example.net",
        {"pinned": True, "tags": ["apt29", "phishing"]},
    )
    bare = await _seed_ioc(client, token, case_a, "benign.example.org", None)
    return {"noted": noted, "tagged_pinned": tagged_pinned, "bare": bare, "case_b": case_b}


async def test_only_annotated_iocs_appear_and_pinned_first(client, analyst_token):
    ids = await _seed_notebook(client, analyst_token)

    resp = await client.get(URL, headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    returned = [i["id"] for i in data["items"]]

    assert ids["noted"] in returned
    assert ids["tagged_pinned"] in returned
    assert ids["bare"] not in returned
    # Pinned rows float to the top of the notebook.
    assert returned[0] == ids["tagged_pinned"]


async def test_closed_investigation_iocs_stay_in_the_notebook(client, analyst_token, db_session):
    """The notebook is cross-case *historical* recall: annotated IOCs from a
    CLOSED investigation must still be searchable, not just those on the active
    case. The search scopes by tenant + ownership only — never by case status.
    """
    ids = await _seed_notebook(client, analyst_token)

    # Resolve the now-historical case (parent of the pinned/tagged IOC).
    case_b = await db_session.get(InvestigationRow, ids["case_b"])
    assert case_b is not None
    case_b.status = InvestigationStatus.CLOSED.value
    await db_session.flush()

    resp = await client.get(URL, headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    returned = [i["id"] for i in resp.json()["items"]]
    # The annotated IOC on the closed case is still surfaced (alongside the
    # annotated IOC on the still-open case A).
    assert ids["tagged_pinned"] in returned
    assert ids["noted"] in returned


async def test_q_matches_note_and_tags(client, analyst_token):
    ids = await _seed_notebook(client, analyst_token)

    by_note = await client.get(f"{URL}?q=cobalt strike", headers=auth_header(analyst_token))
    assert by_note.status_code == 200
    note_ids = [i["id"] for i in by_note.json()["items"]]
    assert ids["noted"] in note_ids
    assert ids["tagged_pinned"] not in note_ids

    by_tag = await client.get(f"{URL}?q=apt29", headers=auth_header(analyst_token))
    assert by_tag.status_code == 200
    tag_ids = [i["id"] for i in by_tag.json()["items"]]
    assert ids["tagged_pinned"] in tag_ids
    assert ids["noted"] not in tag_ids


async def test_disposition_filter(client, analyst_token):
    ids = await _seed_notebook(client, analyst_token)

    resp = await client.get(f"{URL}?disposition=under_review", headers=auth_header(analyst_token))
    assert resp.status_code == 200
    returned = [i["id"] for i in resp.json()["items"]]
    assert ids["noted"] in returned
    assert ids["tagged_pinned"] not in returned

    bad = await client.get(f"{URL}?disposition=nonsense", headers=auth_header(analyst_token))
    assert bad.status_code == 422


async def test_plain_analyst_cannot_see_other_analysts_cases(
    client, analyst_token, db_session, admin_user
):
    ids = await _seed_notebook(client, analyst_token)

    # Reassign case B (the pinned/tagged IOC's parent) to another user —
    # a plain-analyst caller must no longer see its notebook entries.
    case_b = await db_session.get(InvestigationRow, ids["case_b"])
    assert case_b is not None
    case_b.assigned_to = admin_user.id
    await db_session.flush()

    resp = await client.get(URL, headers=auth_header(analyst_token))
    assert resp.status_code == 200
    returned = [i["id"] for i in resp.json()["items"]]
    assert ids["noted"] in returned
    assert ids["tagged_pinned"] not in returned


async def test_requires_auth(client):
    resp = await client.get(URL)
    assert resp.status_code == 401
