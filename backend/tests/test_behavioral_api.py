"""API tests for the Behavioral Hunter router (#114 Phase A).

Exercises the vertical against the in-memory SQLite app: seed an outlier via
the service, then list / set-intent / feedback-benign / promote through the
HTTP layer, plus RBAC and org-scoping guards. Also covers the scheduler job
+ config-flag wiring (mirrors test_hunt_scheduler.py).
"""

from datetime import UTC, datetime, timedelta

import pytest_asyncio
from btagent_shared.types.behavioral import EntityKind, ProfileType
from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import behavioral_service as svc

# --------------------------------------------------------------------------- #
# Fixture: a persisted, committed outlier the HTTP tests act on.
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def seeded_outlier(db_session):
    """Build a baseline + detect one outlier, committed so the app sees it."""
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-API"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common_pwsh"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_api",
        event_vector=[0.0, 1.0],
        event_pattern_key="encoded_pwsh",
        raw_event_excerpt="winword.exe -> powershell -enc <b64>",
    )
    await db_session.commit()
    return out


# --- list + get ---


async def test_list_outliers_org_scoped_and_paginated(client, analyst_token, seeded_outlier):
    resp = await client.get("/api/v1/behavioral/outliers", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] >= 1
    ids = {o["id"] for o in data["items"]}
    assert seeded_outlier.id in ids


async def test_list_outliers_filters_by_intent_label(
    client, analyst_token, admin_token, seeded_outlier
):
    # Before any verdict, a malicious filter returns none of ours.
    resp = await client.get(
        "/api/v1/behavioral/outliers?intent_label=malicious",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert seeded_outlier.id not in {o["id"] for o in resp.json()["items"]}

    # Label it, then it shows up under the filter.
    set_resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/intent",
        json={"intent_label": "malicious", "rationale": "confirmed C2"},
        headers=auth_header(analyst_token),
    )
    assert set_resp.status_code == 200, set_resp.text
    assert set_resp.json()["intent_label"] == "malicious"

    resp2 = await client.get(
        "/api/v1/behavioral/outliers?intent_label=malicious",
        headers=auth_header(analyst_token),
    )
    assert seeded_outlier.id in {o["id"] for o in resp2.json()["items"]}


async def test_get_unknown_outlier_404(client, analyst_token):
    resp = await client.get(
        "/api/v1/behavioral/outliers/bout_nope", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


async def test_outliers_require_auth(client):
    resp = await client.get("/api/v1/behavioral/outliers")
    assert resp.status_code == 401


# --- set-intent (triage) ---


async def test_set_intent_persists_label_and_rationale(client, analyst_token, seeded_outlier):
    resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/intent",
        json={"intent_label": "suspicious", "rationale": "rare encoded payload"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["intent_label"] == "suspicious"
    assert "rare encoded" in body["intent_rationale"]


# --- feedback-benign ---


async def test_feedback_benign_requires_benign_label(client, analyst_token, seeded_outlier):
    # Labeled suspicious -> feedback-benign is a 400.
    await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/intent",
        json={"intent_label": "suspicious", "rationale": "x"},
        headers=auth_header(analyst_token),
    )
    resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/feedback-benign",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 400, resp.text


async def test_feedback_benign_folds_into_baseline(client, analyst_token, seeded_outlier):
    await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/intent",
        json={"intent_label": "benign", "rationale": "admin tooling"},
        headers=auth_header(analyst_token),
    )
    resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/feedback-benign",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text


# --- promote (RBAC) ---


async def test_promote_requires_senior(client, analyst_token, seeded_outlier):
    resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/promote",
        json={"technique_ids": ["T1059.001"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403, resp.text


async def test_promote_lands_in_hunt_findings(client, admin_token, seeded_outlier):
    resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/promote",
        json={"technique_ids": ["T1059.001"]},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding_id"].startswith("hfnd_")


async def test_promote_is_idempotent_on_retry(client, admin_token, seeded_outlier, db_session):
    """A retried promote returns the existing finding, not a duplicate insert."""
    from sqlalchemy import func, select

    from btagent_backend.db.models_hunt import HuntFindingRow

    first = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/promote",
        json={"technique_ids": ["T1059.001"]},
        headers=auth_header(admin_token),
    )
    assert first.status_code == 201, first.text
    finding_id = first.json()["finding_id"]

    count_stmt = select(func.count()).select_from(HuntFindingRow)
    after_first = int((await db_session.execute(count_stmt)).scalar_one())

    # Retry: same finding id back, and no second HuntFinding row written.
    retry = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/promote",
        json={"technique_ids": ["T1059.001"]},
        headers=auth_header(admin_token),
    )
    assert retry.status_code == 201, retry.text
    assert retry.json()["finding_id"] == finding_id

    after_retry = int((await db_session.execute(count_stmt)).scalar_one())
    assert after_retry == after_first


# --- classify endpoint (no model registered -> row unchanged, 200) ---


async def test_classify_without_model_returns_unchanged(client, analyst_token, seeded_outlier):
    resp = await client.post(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/classify",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["intent_label"] is None


# ============================================================================ #
# Scheduler job + config flag (#114) — mirrors test_hunt_scheduler.py
# ============================================================================ #


def _settings(**env):
    from btagent_backend.config import Settings

    return Settings(env="test", **env)


def test_behavioral_schedule_enabled_derives_from_mock_connectors():
    assert _settings(mock_connectors=True).behavioral_schedule_enabled is True
    assert _settings(mock_connectors=False).behavioral_schedule_enabled is False


def test_behavioral_schedule_enabled_explicit_override_wins():
    assert (
        _settings(
            mock_connectors=False, behavioral_schedule_enabled=True
        ).behavioral_schedule_enabled
        is True
    )
    assert (
        _settings(
            mock_connectors=True, behavioral_schedule_enabled=False
        ).behavioral_schedule_enabled
        is False
    )


async def test_baseline_sweep_warns_when_no_telemetry_wired(monkeypatch, caplog, db_session):
    """With the schedule disabled (mocks off), the sweep runs the stale-entity
    pass but logs a single 'no telemetry source wired' warning and builds no
    baselines.

    The job opens its own session via ``async_session_factory``; we point that
    at the test session factory so it shares the in-memory DB connection that
    ``db_session`` has already made live in this event loop (in-memory SQLite
    is per-connection, so the job must not open a cold connection in a new
    loop). Seeds a backdated entity so the stale-entity pass has something to
    count.
    """
    import logging

    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    # Seed a stale entity in the test's live connection.
    stale = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.USER, canonical_id="abandoned-sweep"
    )
    stale.last_seen = datetime.now(UTC) - timedelta(days=90)
    await db_session.commit()

    # Make the job's own-session path reuse this loop's session/connection.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="btagent.scheduler.jobs"):
            result = await jobs.behavioral_baseline_sweep({})
        assert result["baselines_built"] == 0
        assert result["stale_entities"] >= 1
        warnings = [r for r in caplog.records if "no telemetry source wired" in r.message]
        assert len(warnings) == 1
        assert "BTAGENT_BEHAVIORAL_SCHEDULE_ENABLED=true" in warnings[0].message
    finally:
        get_settings.cache_clear()
