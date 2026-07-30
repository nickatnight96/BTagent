"""Tests for the E2E test-seed routes (``api/v1/test_seed.py``).

The whole point of that module is a pair of hard edges, both pinned here:

* **The environment gate.** Outside ``BTAGENT_ENV=test`` every route answers
  404 — indistinguishable from an unregistered route. A regression that
  weakens this to 403 (probeable) or 200 (a production write path into
  pipeline-owned stores) is the failure mode this file exists to catch.
* **Normal auth inside the gate.** Test mode does not relax anything else:
  callers must authenticate, hold ``hunt:create``, and can only write rows
  stamped with their own org. The cross-org outlier attempt must 404 like
  every other IDOR probe in the codebase.

Shared-DB isolation: per-test orgs via ``generate_id("org")``, mirroring
``test_taxii_feeds.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import OrganizationRow, UserRow

ENTITY_BODY = {"kind": "host", "canonical_id": "dc01.corp.test", "enrichment": {"os": "win"}}

PROPOSAL_BODY = {
    "cluster_id": "cl_test_seed",
    "score": 0.82,
    "hunt_input": {
        "adversaries": [],
        "ttps": ["T1059.001"],
        "iocs": [],
        "scope": {
            "environments": [],
            "hosts": [],
            "date_from": None,
            "date_to": None,
            "backends": [],
        },
    },
    "rationale": "Cross-inv pattern: T1059.001 in 3 closed investigations.",
    "state": "proposed",
}


def _make_org(db_session: AsyncSession) -> OrganizationRow:
    org = OrganizationRow(
        id=generate_id("org"),
        name=f"Org {generate_id('n')}",
        created_at=datetime.now(UTC),
    )
    db_session.add(org)
    return org


async def _make_user(db_session: AsyncSession, *, org_id: str, role: str) -> tuple[UserRow, str]:
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"{role}_{generate_id('u')}",
        email=f"{generate_id('e')}@btagent.test",
        password_hash=hash_password("Seed-P@ss-1!"),
        role=role,
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    # org_id must ride the token: CurrentUser.org_id is read from the JWT
    # payload (AUTH-B1), not looked up from the users row.
    token = create_token_pair(user.id, user.username, user.role, org_id=org_id).access_token
    return user, token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# The environment gate
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_all_seed_routes_404_outside_test_env(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    """Outside BTAGENT_ENV=test the routes must look unregistered — 404 even
    for a fully-authorized admin, on every route, before any body validation
    (a malformed body must not turn the probe into a distinguishable 422)."""
    from btagent_backend.api.v1 import test_seed as mod

    org = _make_org(db_session)
    await db_session.flush()
    _, token = await _make_user(db_session, org_id=org.id, role="admin")

    monkeypatch.setattr(mod, "get_settings", lambda: SimpleNamespace(env="prod"))
    for path, body in [
        ("/api/v1/behavioral/test/entities", ENTITY_BODY),
        ("/api/v1/behavioral/test/outliers", {"not": "even valid"}),
        ("/api/v1/pattern/test/proposals", PROPOSAL_BODY),
    ]:
        resp = await client.post(path, json=body, headers=_auth(token))
        assert resp.status_code == 404, f"{path}: expected 404 in prod, got {resp.status_code}"


@pytest.mark.asyncio
async def test_seed_routes_require_auth_even_in_test_env(client: AsyncClient):
    """The gate composes with auth — anonymous callers never reach the body."""
    resp = await client.post("/api/v1/behavioral/test/entities", json=ENTITY_BODY)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_seed_routes_enforce_hunt_create(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.flush()
    _, token = await _make_user(db_session, org_id=org.id, role="viewer")

    resp = await client.post(
        "/api/v1/behavioral/test/entities", json=ENTITY_BODY, headers=_auth(token)
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Behavioral seeding
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_seed_entity_then_outlier_round_trip(client: AsyncClient, db_session: AsyncSession):
    """The E2E flow: seed entity → seed outlier → both readable via the
    product API, stamped with the caller's org."""
    org = _make_org(db_session)
    await db_session.flush()
    _, token = await _make_user(db_session, org_id=org.id, role="analyst")

    ent = await client.post(
        "/api/v1/behavioral/test/entities",
        json={"kind": "user", "canonical_id": f"svc-{generate_id('c')}"},
        headers=_auth(token),
    )
    assert ent.status_code == 201, ent.text
    entity_id = ent.json()["id"]

    out = await client.post(
        "/api/v1/behavioral/test/outliers",
        json={
            "entity_id": entity_id,
            "profile_type": "cmdline_embedding",
            "event_id": "evt_seed_1",
            "cosine_distance": 0.85,
            "frequency_rank": 0,
            "raw_event_excerpt": "powershell.exe -enc AAAA",
        },
        headers=_auth(token),
    )
    assert out.status_code == 201, out.text
    outlier_id = out.json()["id"]

    listed = await client.get("/api/v1/behavioral/outliers", headers=_auth(token))
    assert listed.status_code == 200
    ids = [o["id"] for o in listed.json()["items"]]
    assert outlier_id in ids


@pytest.mark.asyncio
async def test_seed_entity_upserts_on_org_kind_canonical_id(
    client: AsyncClient, db_session: AsyncSession
):
    """Re-seeding the same identity returns the SAME row — the unique index
    (org, kind, canonical_id) must never be violated by a spec re-run."""
    org = _make_org(db_session)
    await db_session.flush()
    _, token = await _make_user(db_session, org_id=org.id, role="analyst")

    body = {"kind": "host", "canonical_id": f"dup-{generate_id('c')}.corp"}
    first = await client.post("/api/v1/behavioral/test/entities", json=body, headers=_auth(token))
    second = await client.post("/api/v1/behavioral/test/entities", json=body, headers=_auth(token))
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["id"] == second.json()["id"]


@pytest.mark.asyncio
async def test_seed_outlier_cross_org_entity_404s(client: AsyncClient, db_session: AsyncSession):
    """A caller cannot attach an outlier to another tenant's entity — the
    foreign entity id must 404 exactly like a nonexistent one."""
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.flush()
    _, token_a = await _make_user(db_session, org_id=org_a.id, role="analyst")
    _, token_b = await _make_user(db_session, org_id=org_b.id, role="analyst")

    ent = await client.post(
        "/api/v1/behavioral/test/entities",
        json={"kind": "host", "canonical_id": f"a-{generate_id('c')}.corp"},
        headers=_auth(token_a),
    )
    entity_a = ent.json()["id"]

    resp = await client.post(
        "/api/v1/behavioral/test/outliers",
        json={
            "entity_id": entity_a,
            "profile_type": "cmdline_embedding",
            "event_id": "evt_xorg",
            "cosine_distance": 0.5,
        },
        headers=_auth(token_b),
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Pattern-proposal seeding
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_seed_proposal_round_trip_and_cluster_upsert(
    client: AsyncClient, db_session: AsyncSession
):
    org = _make_org(db_session)
    await db_session.flush()
    _, token = await _make_user(db_session, org_id=org.id, role="analyst")

    body = dict(PROPOSAL_BODY, cluster_id=f"cl_{generate_id('c')}")
    first = await client.post("/api/v1/pattern/test/proposals", json=body, headers=_auth(token))
    assert first.status_code == 201, first.text
    proposal_id = first.json()["id"]

    # Readable through the product API, in the caller's org only.
    listed = await client.get("/api/v1/pattern/proposals", headers=_auth(token))
    assert listed.status_code == 200
    assert proposal_id in [p["id"] for p in listed.json()["items"]]

    # Same cluster_id upserts (unique index org/cluster_id), updating state.
    second = await client.post(
        "/api/v1/pattern/test/proposals",
        json=dict(body, state="snoozed", score=0.5),
        headers=_auth(token),
    )
    assert second.status_code == 201
    assert second.json()["id"] == proposal_id


@pytest.mark.asyncio
async def test_seed_proposal_rejects_malformed_hunt_input(
    client: AsyncClient, db_session: AsyncSession
):
    """The store must stay well-formed — a hunt_input that isn't a HuntInput
    is refused, not persisted for the UI to choke on later."""
    org = _make_org(db_session)
    await db_session.flush()
    _, token = await _make_user(db_session, org_id=org.id, role="analyst")

    resp = await client.post(
        "/api/v1/pattern/test/proposals",
        json=dict(PROPOSAL_BODY, cluster_id=f"cl_{generate_id('c')}", hunt_input={"bogus": 1}),
        headers=_auth(token),
    )
    assert resp.status_code == 422
