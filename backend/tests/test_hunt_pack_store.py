"""Per-org hunt-pack store + under-firing advisory (#112).

Covers the two remaining #112 gaps:

* the **pack store** — the scheduled runner used to run a hardcoded
  ``('windows_baseline',)`` for every org, so ~4 of the 90 shipped builtin
  rules ever ran on a schedule and nobody could turn a pack on or off. Tests
  pin the resolution semantics (default fallback, explicit enable/disable),
  that the *runner* honours them, org-scoping, and the RBAC-gated API.
* **under-firing** — the mirror of the noise baseline: rules with a 60-day
  zero-hit record, surfaced for review.

Shared-DB discipline: every count/identity assertion runs against a dedicated
per-test org (``generate_id("org")``), never ``DEFAULT_ORG_ID`` — the backend
suite shares one session-scoped SQLite and committed rows outlive the test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow, UserRow
from btagent_backend.db.models_hunt import HuntPackRunRow, OrgHuntPackRow
from btagent_backend.services import hunt_pack_store as store
from btagent_backend.services import noise_baseline as nb
from tests.helpers import auth_header

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def fresh_org(db_session):
    """A dedicated per-test org (FK target for pack rows + run history)."""
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"Pack Org {oid}", created_at=NOW))
    await db_session.commit()
    return oid


@pytest_asyncio.fixture()
async def two_orgs(db_session):
    a, b = generate_id("org"), generate_id("org")
    for oid in (a, b):
        db_session.add(OrganizationRow(id=oid, name=f"Pack Org {oid}", created_at=NOW))
    await db_session.commit()
    return a, b


async def _user_token(db, *, role: str, org_id: str = DEFAULT_ORG_ID) -> str:
    suffix = generate_id("n")[-8:]
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"packs_{role}_{suffix}",
        email=f"packs_{role}_{suffix}@btagent.test",
        password_hash=hash_password("Packs-P@ss-123!"),
        role=role,
        created_at=NOW,
    )
    db.add(user)
    await db.commit()
    return create_token_pair(user.id, user.username, user.role).access_token


@pytest_asyncio.fixture()
async def senior_token(db_session) -> str:
    """A senior_analyst — holds ``huntpack:manage``."""
    return await _user_token(db_session, role="senior_analyst")


def _run_row(
    *,
    org_id: str,
    pack_id: str,
    rule_stats: dict,
    started_at: datetime,
    status: str = "completed",
) -> HuntPackRunRow:
    return HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=org_id,
        run_id=generate_id("hrun"),
        pack_id=pack_id,
        pack_name=f"Pack {pack_id}",
        pack_version="1.0.0",
        backends=["splunk"],
        rule_stats=rule_stats,
        hit_count=sum(int(v.get("hits", 0)) for v in rule_stats.values()),
        error_count=0,
        findings_created=0,
        status=status,
        progress={},
        started_at=started_at,
        completed_at=started_at,
    )


# --------------------------------------------------------------------------- #
# Pure resolution semantics
# --------------------------------------------------------------------------- #


def test_no_rows_falls_back_to_the_builtin_default():
    assert store.resolve_enabled({}) == sorted(store.DEFAULT_BUILTIN_PACKS)


def test_explicit_disable_of_a_default_pack_removes_it():
    explicit = dict.fromkeys(store.DEFAULT_BUILTIN_PACKS, False)
    assert store.resolve_enabled(explicit) == []


def test_enabling_an_extra_pack_keeps_the_default_running():
    """Turning one pack on must not silently switch the baseline pack off."""
    resolved = store.resolve_enabled({"identity": True})
    assert "identity" in resolved
    for name in store.DEFAULT_BUILTIN_PACKS:
        assert name in resolved


def test_unknown_pack_names_are_filtered_against_the_shipped_catalog():
    resolved = store.resolve_enabled(
        {"not_a_real_pack": True, "identity": True},
        known=("identity", "windows_baseline"),
    )
    assert resolved == ["identity", "windows_baseline"]


def test_empty_catalog_means_unknown_not_empty():
    """An engine-less image must not resolve every pack away."""
    assert store.resolve_enabled({"identity": True}, known=()) == sorted(
        {"identity", *store.DEFAULT_BUILTIN_PACKS}
    )


def test_shipped_catalog_covers_more_than_the_default():
    """The whole point of the store: 14 packs ship, one used to run."""
    names = store.builtin_pack_names()
    assert set(store.DEFAULT_BUILTIN_PACKS) <= set(names)
    assert len(names) > len(store.DEFAULT_BUILTIN_PACKS)


# --------------------------------------------------------------------------- #
# Store reads / writes
# --------------------------------------------------------------------------- #


async def test_enabled_pack_names_falls_back_for_an_org_with_no_rows(db_session, fresh_org):
    assert await store.enabled_pack_names(db_session, org_id=fresh_org) == sorted(
        store.DEFAULT_BUILTIN_PACKS
    )


async def test_set_pack_enabled_installs_then_toggles(db_session, fresh_org):
    row = await store.set_pack_enabled(
        db_session, org_id=fresh_org, pack_id="identity", enabled=True, updated_by="usr_1"
    )
    await db_session.commit()
    assert row.enabled is True
    assert row.installed_at is not None
    assert row.updated_by == "usr_1"
    assert "identity" in await store.enabled_pack_names(db_session, org_id=fresh_org)

    await store.set_pack_enabled(
        db_session, org_id=fresh_org, pack_id="identity", enabled=False, updated_by="usr_2"
    )
    await db_session.commit()
    rows = await store.list_org_packs(db_session, org_id=fresh_org)
    assert len(rows) == 1  # upsert, not a second row
    assert rows[0].enabled is False
    assert rows[0].updated_by == "usr_2"
    assert "identity" not in await store.enabled_pack_names(db_session, org_id=fresh_org)


async def test_set_pack_enabled_rejects_an_unknown_pack(db_session, fresh_org):
    with pytest.raises(store.UnknownPackError):
        await store.set_pack_enabled(
            db_session, org_id=fresh_org, pack_id="../etc/passwd", enabled=True
        )


async def test_store_is_org_scoped(db_session, two_orgs):
    org_a, org_b = two_orgs
    await store.set_pack_enabled(db_session, org_id=org_a, pack_id="identity", enabled=True)
    for name in store.DEFAULT_BUILTIN_PACKS:
        await store.set_pack_enabled(db_session, org_id=org_a, pack_id=name, enabled=False)
    await db_session.commit()

    assert await store.enabled_pack_names(db_session, org_id=org_a) == ["identity"]
    # Org B never touched the store — untouched fallback, no leakage.
    assert await store.enabled_pack_names(db_session, org_id=org_b) == sorted(
        store.DEFAULT_BUILTIN_PACKS
    )
    assert await store.list_org_packs(db_session, org_id=org_b) == []


async def test_pack_catalog_marks_default_enabled_without_a_row(db_session, fresh_org):
    catalog = await store.pack_catalog(db_session, org_id=fresh_org)
    by_id = {e.pack_id: e for e in catalog.items}
    assert by_id  # the engine ships packs in the test env
    default_name = store.DEFAULT_BUILTIN_PACKS[0]
    assert by_id[default_name].enabled is True
    assert by_id[default_name].installed is False
    assert by_id[default_name].default_enabled is True
    # A non-default pack is off until someone enables it.
    assert by_id["identity"].enabled is False
    assert catalog.default_packs == list(store.DEFAULT_BUILTIN_PACKS)
    # The catalog carries the manifest id run history uses, so the UI can join.
    assert by_id[default_name].manifest_pack_id.startswith("hpack_")
    assert by_id[default_name].rule_count > 0


# --------------------------------------------------------------------------- #
# The runner honours the store
# --------------------------------------------------------------------------- #


async def _run_for(db, org_id: str):
    from btagent_backend.services import hunt_pack_run_service as prs

    return await prs.run_pack_and_ingest(
        db, org_id=org_id, backends=["splunk"], emit_events=False, checkpoint=False
    )


async def test_runner_falls_back_to_the_builtin_default(db_session, fresh_org):
    pytest.importorskip("btagent_engine.hunting.runner")
    runs = await _run_for(db_session, fresh_org)
    default_pack = store.list_builtin_packs()[0]
    expected = {
        p.manifest_pack_id
        for p in store.list_builtin_packs()
        if p.pack_id in store.DEFAULT_BUILTIN_PACKS
    }
    assert {r.pack_id for r in runs} == expected
    assert default_pack  # catalog non-empty


async def test_runner_runs_exactly_the_enabled_packs(db_session, fresh_org):
    pytest.importorskip("btagent_engine.hunting.runner")
    await store.set_pack_enabled(db_session, org_id=fresh_org, pack_id="identity", enabled=True)
    for name in store.DEFAULT_BUILTIN_PACKS:
        await store.set_pack_enabled(db_session, org_id=fresh_org, pack_id=name, enabled=False)
    await db_session.commit()

    runs = await _run_for(db_session, fresh_org)
    identity_id = next(
        p.manifest_pack_id for p in store.list_builtin_packs() if p.pack_id == "identity"
    )
    assert {r.pack_id for r in runs} == {identity_id}


async def test_runner_skips_the_sweep_when_every_pack_is_disabled(db_session, fresh_org):
    pytest.importorskip("btagent_engine.hunting.runner")
    for name in store.DEFAULT_BUILTIN_PACKS:
        await store.set_pack_enabled(db_session, org_id=fresh_org, pack_id=name, enabled=False)
    await db_session.commit()

    assert await _run_for(db_session, fresh_org) == []
    rows = await store.list_org_packs(db_session, org_id=fresh_org)
    assert all(r.enabled is False for r in rows)


async def test_explicit_pack_names_bypass_the_store(db_session, fresh_org):
    """Ad-hoc / test runs still name their own packs."""
    pytest.importorskip("btagent_engine.hunting.runner")
    from btagent_backend.services import hunt_pack_run_service as prs

    for name in store.DEFAULT_BUILTIN_PACKS:
        await store.set_pack_enabled(db_session, org_id=fresh_org, pack_id=name, enabled=False)
    await db_session.commit()

    runs = await prs.run_pack_and_ingest(
        db_session,
        org_id=fresh_org,
        pack_names=["identity"],
        backends=["splunk"],
        emit_events=False,
        checkpoint=False,
    )
    assert len(runs) == 1


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


async def test_catalog_endpoint_lists_packs_for_an_analyst(client: AsyncClient, analyst_token: str):
    resp = await client.get("/api/v1/hunt/packs", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == len(body["items"]) > 0
    entry = body["items"][0]
    assert {"pack_id", "manifest_pack_id", "enabled", "installed", "rule_count"} <= set(entry)


async def test_catalog_endpoint_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/hunt/packs")
    assert resp.status_code in (401, 403)


async def test_enable_requires_senior_analyst(client: AsyncClient, analyst_token: str):
    resp = await client.put(
        "/api/v1/hunt/packs/identity",
        json={"enabled": True},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403


async def test_enable_then_disable_round_trips(client: AsyncClient, senior_token: str, db_session):
    try:
        resp = await client.put(
            "/api/v1/hunt/packs/identity",
            json={"enabled": True},
            headers=auth_header(senior_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["enabled"] is True
        assert resp.json()["installed"] is True

        catalog = await client.get("/api/v1/hunt/packs", headers=auth_header(senior_token))
        entry = next(e for e in catalog.json()["items"] if e["pack_id"] == "identity")
        assert entry["enabled"] is True
        assert entry["updated_by"]

        resp = await client.put(
            "/api/v1/hunt/packs/identity",
            json={"enabled": False},
            headers=auth_header(senior_token),
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
    finally:
        # The senior fixture lives in DEFAULT_ORG_ID (the shared inbox org) —
        # drop the row so later tests see the pristine fallback.
        row = await db_session.get(OrgHuntPackRow, (DEFAULT_ORG_ID, "identity"))
        if row is not None:
            await db_session.delete(row)
            await db_session.commit()


async def test_enable_unknown_pack_404s(client: AsyncClient, senior_token: str):
    resp = await client.put(
        "/api/v1/hunt/packs/definitely_not_a_pack",
        json={"enabled": True},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Under-firing (#112 Phase C)
# --------------------------------------------------------------------------- #


def _stat(hits: int = 0, errors: int = 0, title: str = "Silent rule") -> dict:
    return {"title": title, "hits": hits, "errors": errors}


class _Run:
    """Minimal ``_RunLike`` stand-in for the pure analysis."""

    def __init__(
        self, *, started_at, rule_stats, pack_id="p1", status="completed", rules_not_run=()
    ):
        self.pack_id = pack_id
        self.pack_name = "Pack One"
        self.rule_stats = rule_stats
        self.status = status
        self.started_at = started_at
        self.rules_not_run = list(rules_not_run)


def test_under_firing_flags_a_rule_silent_across_the_window():
    runs = [
        _Run(started_at=NOW - timedelta(days=d), rule_stats={"r1": _stat()}) for d in (1, 20, 55)
    ]
    items = nb.compute_under_firing(runs, now=NOW)
    assert [i.rule_id for i in items] == ["r1"]
    assert items[0].runs_observed == 3
    assert items[0].total_hits == 0
    assert items[0].days_silent == 54
    assert items[0].window_days == nb.UNDER_FIRING_WINDOW_DAYS


def test_under_firing_ignores_a_rule_that_hit_once():
    runs = [
        _Run(started_at=NOW - timedelta(days=1), rule_stats={"r1": _stat()}),
        _Run(started_at=NOW - timedelta(days=20), rule_stats={"r1": _stat(hits=1)}),
        _Run(started_at=NOW - timedelta(days=55), rule_stats={"r1": _stat()}),
    ]
    assert nb.compute_under_firing(runs, now=NOW) == []


def test_under_firing_needs_min_runs_inside_the_window():
    runs = [
        _Run(started_at=NOW - timedelta(days=1), rule_stats={"r1": _stat()}),
        _Run(started_at=NOW - timedelta(days=2), rule_stats={"r1": _stat()}),
        # Outside the 60-day window — must not count toward min_runs.
        _Run(started_at=NOW - timedelta(days=90), rule_stats={"r1": _stat()}),
    ]
    assert nb.compute_under_firing(runs, now=NOW) == []


def test_under_firing_excludes_an_errored_rule():
    """A rule that could not execute is dark, not silent."""
    runs = [
        _Run(started_at=NOW - timedelta(days=1), rule_stats={"r1": _stat(errors=2)}),
        _Run(started_at=NOW - timedelta(days=20), rule_stats={"r1": _stat()}),
        _Run(started_at=NOW - timedelta(days=55), rule_stats={"r1": _stat()}),
    ]
    assert nb.compute_under_firing(runs, now=NOW) == []


def test_under_firing_ignores_failed_runs():
    runs = [
        _Run(started_at=NOW - timedelta(days=d), rule_stats={"r1": _stat()}, status="failed")
        for d in (1, 20, 55)
    ]
    assert nb.compute_under_firing(runs, now=NOW) == []


def test_under_firing_tracks_rules_per_pack():
    runs = []
    for d in (1, 20, 55):
        runs.append(_Run(started_at=NOW - timedelta(days=d), rule_stats={"r1": _stat()}))
        runs.append(
            _Run(
                started_at=NOW - timedelta(days=d),
                rule_stats={"r1": _stat(hits=3)},
                pack_id="p2",
            )
        )
    items = nb.compute_under_firing(runs, now=NOW)
    assert [(i.pack_id, i.rule_id) for i in items] == [("p1", "r1")]


async def test_under_firing_query_is_org_scoped(db_session, two_orgs):
    org_a, org_b = two_orgs
    for d in (1, 20, 55):
        db_session.add(
            _run_row(
                org_id=org_a,
                pack_id="hpack_a",
                rule_stats={"ra": _stat(title="Silent A")},
                started_at=NOW - timedelta(days=d),
            )
        )
        db_session.add(
            _run_row(
                org_id=org_b,
                pack_id="hpack_b",
                rule_stats={"rb": _stat(title="Silent B")},
                started_at=NOW - timedelta(days=d),
            )
        )
    await db_session.commit()

    report_a = await nb.under_firing(db_session, org_id=org_a, now=NOW)
    assert [i.rule_id for i in report_a.items] == ["ra"]
    assert report_a.runs_analyzed == 3
    assert report_a.window_days == 60

    report_b = await nb.under_firing(db_session, org_id=org_b, now=NOW)
    assert [i.rule_id for i in report_b.items] == ["rb"]


async def test_noise_baseline_payload_carries_under_firing(db_session, fresh_org):
    for d in (1, 20, 55):
        db_session.add(
            _run_row(
                org_id=fresh_org,
                pack_id="hpack_x",
                rule_stats={"quiet": _stat(title="Quiet rule")},
                started_at=NOW - timedelta(days=d),
            )
        )
    await db_session.commit()

    payload = await nb.noise_baseline(db_session, org_id=fresh_org, now=NOW)
    assert payload.items == []  # nothing over-firing
    assert [i.rule_id for i in payload.under_firing] == ["quiet"]
    assert payload.under_firing_window_days == 60


async def test_under_firing_endpoint(client: AsyncClient, analyst_token: str, db_session):
    """The route reads the caller's org only (analyst lives in DEFAULT_ORG)."""
    marker = f"silent_{generate_id('n')[-8:]}"
    rows = [
        _run_row(
            org_id=DEFAULT_ORG_ID,
            pack_id=f"hpack_{marker}",
            rule_stats={marker: _stat(title="Endpoint silent rule")},
            started_at=datetime.now(UTC) - timedelta(days=d),
        )
        for d in (1, 5, 9)
    ]
    for row in rows:
        db_session.add(row)
    await db_session.commit()
    try:
        resp = await client.get("/api/v1/hunt/under-firing", headers=auth_header(analyst_token))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["window_days"] == 60
        mine = [i for i in body["items"] if i["rule_id"] == marker]
        assert len(mine) == 1
        assert mine[0]["total_hits"] == 0
        assert mine[0]["runs_observed"] == 3
    finally:
        for row in rows:
            await db_session.delete(row)
        await db_session.commit()


async def test_under_firing_endpoint_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/hunt/under-firing")
    assert resp.status_code in (401, 403)
