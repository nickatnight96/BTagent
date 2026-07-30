"""Tests for the org-custom pack store (#112 slice 2).

Three layers, one contract: a bundle that persists is a bundle the sweep can
run. The service validates through the engine's ``load_pack_from_bundle``
(the same loader the builtin packs use), the API gates writes on
``huntpack:manage`` and audits them, and the scheduled sweep runs stored
bundles alongside the builtin set.

Shared-DB isolation: per-test orgs via ``generate_id("org")``, org_id on the
token (CurrentUser reads it from the JWT payload, AUTH-B1).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import OrganizationRow, UserRow
from btagent_backend.services import org_custom_pack_service as svc

MANIFEST = """\
name: Org Custom Pack
version: 1.0.0
description: Uploaded in tests.
rules:
  - file: encoded_ps.yml
    enabled: true
"""

RULE = """\
title: Encoded PowerShell (custom)
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: "-enc"
  condition: selection
level: high
tags:
  - attack.t1059.001
"""

BUNDLE = {"manifest_yaml": MANIFEST, "rule_files": {"encoded_ps.yml": RULE}}


def _make_org(db_session: AsyncSession) -> OrganizationRow:
    org = OrganizationRow(
        id=generate_id("org"), name=f"Org {generate_id('n')}", created_at=datetime.now(UTC)
    )
    db_session.add(org)
    return org


async def _make_user(db_session: AsyncSession, *, org_id: str, role: str) -> tuple[UserRow, str]:
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"{role}_{generate_id('u')}",
        email=f"{generate_id('e')}@btagent.test",
        password_hash=hash_password("Packs-P@ss-1!"),
        role=role,
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    token = create_token_pair(user.id, user.username, user.role, org_id=org_id).access_token
    return user, token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_validates_and_persists_identity_fields(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    row, created = await svc.create_or_update_pack(
        db_session,
        org_id=org.id,
        manifest_yaml=MANIFEST,
        rule_files={"encoded_ps.yml": RULE},
        created_by="usr_test",
    )
    assert created is True
    assert row.name == "Org Custom Pack"
    assert row.version == "1.0.0"
    assert row.rule_count == 1
    assert row.pack_id.startswith("hpack_")
    # The stored bundle round-trips through the engine loader (the sweep path).
    pack = svc.load_row_pack(row)
    assert pack.id == row.pack_id
    assert [r.title for r in pack.rules] == ["Encoded PowerShell (custom)"]


@pytest.mark.asyncio
async def test_same_identity_reupload_updates_in_place(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    first, created1 = await svc.create_or_update_pack(
        db_session, org_id=org.id, manifest_yaml=MANIFEST, rule_files={"encoded_ps.yml": RULE}
    )
    tuned = MANIFEST.replace("Uploaded in tests.", "Tuned description.")
    second, created2 = await svc.create_or_update_pack(
        db_session, org_id=org.id, manifest_yaml=tuned, rule_files={"encoded_ps.yml": RULE}
    )
    assert created1 is True and created2 is False
    assert second.id == first.id  # same row, not a duplicate
    assert second.description == "Tuned description."
    assert len(await svc.list_packs(db_session, org_id=org.id)) == 1


@pytest.mark.asyncio
async def test_invalid_bundle_and_builtin_collision_are_refused(db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.commit()

    with pytest.raises(svc.InvalidPackBundle, match="has no 'title'"):
        await svc.create_or_update_pack(
            db_session,
            org_id=org.id,
            manifest_yaml=MANIFEST,
            rule_files={"encoded_ps.yml": "detection:\n  condition: sel\n"},
        )

    # A manifest that claims a builtin pack's id is refused — run history
    # would otherwise become ambiguous between the builtin and the upload.
    from btagent_backend.services.hunt_pack_store import list_builtin_packs

    builtin_id = list_builtin_packs()[0].manifest_pack_id
    stolen = f"id: {builtin_id}\n" + MANIFEST
    with pytest.raises(svc.InvalidPackBundle, match="collides with a builtin"):
        await svc.create_or_update_pack(
            db_session, org_id=org.id, manifest_yaml=stolen, rule_files={"encoded_ps.yml": RULE}
        )


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_api_upload_list_delete_round_trip(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.flush()
    _, senior = await _make_user(db_session, org_id=org.id, role="senior_analyst")

    up = await client.post("/api/v1/hunt/packs/custom", json=BUNDLE, headers=_auth(senior))
    assert up.status_code == 201, up.text
    row_id = up.json()["id"]
    assert up.json()["rule_count"] == 1

    listed = await client.get("/api/v1/hunt/packs/custom", headers=_auth(senior))
    assert listed.status_code == 200
    assert [p["id"] for p in listed.json()["items"]] == [row_id]

    gone = await client.delete(f"/api/v1/hunt/packs/custom/{row_id}", headers=_auth(senior))
    assert gone.status_code == 204
    assert (await client.get("/api/v1/hunt/packs/custom", headers=_auth(senior))).json()[
        "total"
    ] == 0


@pytest.mark.asyncio
async def test_api_invalid_bundle_returns_loader_message(
    client: AsyncClient, db_session: AsyncSession
):
    org = _make_org(db_session)
    await db_session.flush()
    _, senior = await _make_user(db_session, org_id=org.id, role="senior_analyst")

    resp = await client.post(
        "/api/v1/hunt/packs/custom",
        json={"manifest_yaml": "{unclosed", "rule_files": {"r.yml": RULE}},
        headers=_auth(senior),
    )
    assert resp.status_code == 422
    assert "not valid YAML" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_api_writes_require_huntpack_manage(client: AsyncClient, db_session: AsyncSession):
    org = _make_org(db_session)
    await db_session.flush()
    _, analyst = await _make_user(db_session, org_id=org.id, role="analyst")

    assert (
        await client.post("/api/v1/hunt/packs/custom", json=BUNDLE, headers=_auth(analyst))
    ).status_code == 403
    assert (
        await client.delete("/api/v1/hunt/packs/custom/ocp_nope", headers=_auth(analyst))
    ).status_code == 403
    # Reading stays hunt:view (analyst+).
    assert (
        await client.get("/api/v1/hunt/packs/custom", headers=_auth(analyst))
    ).status_code == 200


@pytest.mark.asyncio
async def test_api_cross_org_delete_404s(client: AsyncClient, db_session: AsyncSession):
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.flush()
    _, senior_a = await _make_user(db_session, org_id=org_a.id, role="senior_analyst")
    _, senior_b = await _make_user(db_session, org_id=org_b.id, role="senior_analyst")

    up = await client.post("/api/v1/hunt/packs/custom", json=BUNDLE, headers=_auth(senior_a))
    row_id = up.json()["id"]

    # Another tenant's row id must 404 exactly like a nonexistent one, and the
    # row must survive the attempt.
    resp = await client.delete(f"/api/v1/hunt/packs/custom/{row_id}", headers=_auth(senior_b))
    assert resp.status_code == 404
    assert (await client.get("/api/v1/hunt/packs/custom", headers=_auth(senior_a))).json()[
        "total"
    ] == 1


# --------------------------------------------------------------------------- #
# Catalog surfacing (#112 follow-up)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_uploaded_pack_appears_in_the_hunt_pack_catalog(
    client: AsyncClient, db_session: AsyncSession
):
    """An uploaded bundle runs on every sweep, so the catalog must say so.

    The entry carries ``source="custom"``, reads enabled/installed by
    existence, and its ``manifest_pack_id`` is the id the pack's sweep runs
    record — the key the UI joins run history on. Deleting the bundle removes
    the entry.
    """
    org = _make_org(db_session)
    await db_session.flush()
    _, senior = await _make_user(db_session, org_id=org.id, role="senior_analyst")

    up = await client.post("/api/v1/hunt/packs/custom", json=BUNDLE, headers=_auth(senior))
    assert up.status_code == 201, up.text
    row_id = up.json()["id"]
    pack_id = up.json()["pack_id"]

    catalog = (await client.get("/api/v1/hunt/packs", headers=_auth(senior))).json()
    entry = next((e for e in catalog["items"] if e["pack_id"] == pack_id), None)
    assert entry is not None, f"custom pack {pack_id} missing from catalog"
    assert entry["source"] == "custom"
    assert entry["enabled"] is True
    assert entry["installed"] is True
    assert entry["default_enabled"] is False
    assert entry["manifest_pack_id"] == pack_id
    assert entry["rule_count"] == 1
    assert catalog["total"] == len(catalog["items"])

    # Custom packs are enabled by existence — the toggle API must refuse the
    # id rather than persist a row the sweep would ignore.
    put = await client.put(
        f"/api/v1/hunt/packs/{pack_id}", json={"enabled": False}, headers=_auth(senior)
    )
    assert put.status_code == 404

    await client.delete(f"/api/v1/hunt/packs/custom/{row_id}", headers=_auth(senior))
    catalog_after = (await client.get("/api/v1/hunt/packs", headers=_auth(senior))).json()
    assert all(e["pack_id"] != pack_id for e in catalog_after["items"])


@pytest.mark.asyncio
async def test_catalog_custom_entries_are_org_scoped(client: AsyncClient, db_session: AsyncSession):
    org_a = _make_org(db_session)
    org_b = _make_org(db_session)
    await db_session.flush()
    _, senior_a = await _make_user(db_session, org_id=org_a.id, role="senior_analyst")
    _, senior_b = await _make_user(db_session, org_id=org_b.id, role="senior_analyst")

    up = await client.post("/api/v1/hunt/packs/custom", json=BUNDLE, headers=_auth(senior_a))
    pack_id = up.json()["pack_id"]

    catalog_b = (await client.get("/api/v1/hunt/packs", headers=_auth(senior_b))).json()
    assert all(e["pack_id"] != pack_id for e in catalog_b["items"])


# --------------------------------------------------------------------------- #
# Sweep integration
# --------------------------------------------------------------------------- #


@pytest.fixture()
def _mock_connectors(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    from btagent_backend.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_sweep_runs_custom_pack_alongside_builtins(
    db_session: AsyncSession, _mock_connectors
):
    """The payoff: a stored bundle produces its own run-history row on the
    org's scheduled sweep, next to the builtin default set."""
    from btagent_backend.services import hunt_pack_run_service as prs

    org = _make_org(db_session)
    await db_session.commit()
    row, _ = await svc.create_or_update_pack(
        db_session, org_id=org.id, manifest_yaml=MANIFEST, rule_files={"encoded_ps.yml": RULE}
    )
    await db_session.commit()

    run_rows = await prs.run_pack_and_ingest(
        db_session,
        org_id=org.id,
        backends=["splunk"],
        max_hits_per_query=5,
        emit_events=False,
        checkpoint=False,
    )
    by_pack = {r.pack_id: r for r in run_rows}
    # The builtin default set still ran…
    assert any(pid != row.pack_id for pid in by_pack), by_pack.keys()
    # …and the custom pack ran with its own history row.
    assert row.pack_id in by_pack
    custom_run = by_pack[row.pack_id]
    assert custom_run.pack_name == "Org Custom Pack"
    assert custom_run.status in ("completed", "completed_with_errors")
