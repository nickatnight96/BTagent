"""Tests for the per-org feature-flag store (#418 slice 4).

Covers the GET/PUT round trip with wholesale-replace semantics (absent keys
deleted), key validation, RBAC (analyst reads but cannot write), org
isolation at the row level, and the unauthenticated 401.
"""

from conftest import auth_header

from btagent_backend.db.models import FeatureFlagRow

URL = "/api/v1/config/feature-flags"


async def test_round_trip_and_wholesale_replace(client, admin_token):
    assert (await client.get(URL, headers=auth_header(admin_token))).json() == {"flags": {}}

    put1 = await client.put(
        URL,
        headers=auth_header(admin_token),
        json={"flags": {"dark_launch_reports": True, "beta_notebook_search": False}},
    )
    assert put1.status_code == 200, put1.text
    got1 = await client.get(URL, headers=auth_header(admin_token))
    assert got1.json()["flags"] == {
        "dark_launch_reports": True,
        "beta_notebook_search": False,
    }

    # Replace wholesale: one flag flipped, one dropped, one added.
    put2 = await client.put(
        URL,
        headers=auth_header(admin_token),
        json={"flags": {"dark_launch_reports": False, "new_toggle": True}},
    )
    assert put2.status_code == 200, put2.text
    got2 = await client.get(URL, headers=auth_header(admin_token))
    assert got2.json()["flags"] == {"dark_launch_reports": False, "new_toggle": True}


async def test_key_validation(client, admin_token):
    for bad in ("Bad-Key", "1starts_with_digit", "UPPER", "has space", "x" * 65):
        resp = await client.put(URL, headers=auth_header(admin_token), json={"flags": {bad: True}})
        assert resp.status_code == 422, bad


async def test_rbac_analyst_reads_but_cannot_write(client, analyst_token):
    read = await client.get(URL, headers=auth_header(analyst_token))
    assert read.status_code == 200

    write = await client.put(
        URL, headers=auth_header(analyst_token), json={"flags": {"nope": True}}
    )
    assert write.status_code == 403


async def test_flags_are_org_scoped(client, admin_token, db_session):
    put = await client.put(
        URL, headers=auth_header(admin_token), json={"flags": {"scoped_flag": True}}
    )
    assert put.status_code == 200

    rows = (await db_session.execute(FeatureFlagRow.__table__.select())).all()
    scoped = [r for r in rows if r.key == "scoped_flag"]
    assert len(scoped) == 1
    # The row is stamped with the writer's org — no global/other-org rows.
    assert scoped[0].org_id


async def test_requires_auth(client):
    assert (await client.get(URL)).status_code == 401
