"""Tests for the Behavioral Hunter baseline-build cron half (#114 Phase A, task B).

Two layers:

* the ``behavioral_ingest_service.rebuild_baselines_from_edr`` service function,
  driven against a **dedicated per-test org** with a stub EDR + stub embedder so
  the exact per-org baseline count is asserted in isolation (shared-DB rule);
* the ``behavioral_baseline_sweep`` arq job wiring — the disabled gate warns and
  builds nothing; the enabled gate (mocks on) pulls the mock-first CrowdStrike
  telemetry and lands real baselines.
"""

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from btagent_shared.types.behavioral import EntityKind, ProfileType
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select

from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow
from btagent_backend.db.models_behavioral import BehavioralEntityRow, BehavioralProfileRow
from btagent_backend.services import behavioral_ingest_service as ingest
from btagent_backend.services.embedding_service import EmbeddingService


class _StubEmbedder(EmbeddingService):
    @property
    def provider_name(self) -> str:
        return "stub"

    async def generate_embeddings(self, texts: list[str]) -> list[list[float]]:
        # A tiny fixed-length vector is enough — the baseline build only needs a
        # consistent dimension to average into a centroid.
        return [[float(len(t) % 7), 1.0, 0.0] for t in texts]


class _StubEdr:
    """Two hosts of benign ProcessRollup2 telemetry, no network."""

    async def cs_process_telemetry(self, lookback_days: int = 30):
        return {
            "status": "success",
            "lookback_days": lookback_days,
            "events": [
                {
                    "event_id": "e1",
                    "hostname": "HOST-A",
                    "user_name": "u",
                    "filename": "cmd.exe",
                    "parent_image_filename": "explorer.exe",
                    "cmdline": "cmd.exe /c dir",
                },
                {
                    "event_id": "e2",
                    "hostname": "HOST-A",
                    "user_name": "u",
                    "filename": "git.exe",
                    "parent_image_filename": "Code.exe",
                    "cmdline": "git.exe fetch",
                },
                {
                    "event_id": "e3",
                    "hostname": "HOST-B",
                    "user_name": "svc",
                    "filename": "svchost.exe",
                    "parent_image_filename": "services.exe",
                    "cmdline": "svchost.exe -k netsvcs",
                },
                # A telemetry row with no hostname is skipped (nothing to key on).
                {
                    "event_id": "e4",
                    "hostname": "",
                    "user_name": "svc",
                    "filename": "svchost.exe",
                    "parent_image_filename": "services.exe",
                    "cmdline": "svchost.exe -k dcom",
                },
            ],
        }


async def _make_org(db) -> str:
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name="behav-baseline-test", created_at=datetime.now(UTC)))
    await db.flush()
    return org_id


# --------------------------------------------------------------------------- #
# service: rebuild_baselines_from_edr (dedicated org)
# --------------------------------------------------------------------------- #


async def test_rebuild_baselines_from_edr_builds_one_per_host(db_session):
    org_id = await _make_org(db_session)

    summary = await ingest.rebuild_baselines_from_edr(
        db_session,
        org_id=org_id,
        lookback_days=30,
        edr=_StubEdr(),
        embedding_service=_StubEmbedder(),
    )
    assert summary == {"entities": 2, "baselines_built": 2, "events": 3}

    # Exactly two entities + two profiles for THIS org (isolation rule).
    ent_count = (
        await db_session.execute(
            select(func.count())
            .select_from(BehavioralEntityRow)
            .where(BehavioralEntityRow.org_id == org_id)
        )
    ).scalar_one()
    prof_count = (
        await db_session.execute(
            select(func.count())
            .select_from(BehavioralProfileRow)
            .where(BehavioralProfileRow.org_id == org_id)
        )
    ).scalar_one()
    assert ent_count == 2
    assert prof_count == 2

    # HOST-A's baseline learned both its lineages + a cmdline centroid.
    host_a = (
        await db_session.execute(
            select(BehavioralProfileRow)
            .join(BehavioralEntityRow, BehavioralProfileRow.entity_id == BehavioralEntityRow.id)
            .where(
                BehavioralEntityRow.org_id == org_id,
                BehavioralEntityRow.canonical_id == "HOST-A",
            )
        )
    ).scalar_one()
    assert host_a.profile_type == ProfileType.CMDLINE_EMBEDDING.value
    assert set(host_a.frequency_map) == {"explorer.exe>cmd.exe", "code.exe>git.exe"}
    assert host_a.centroid is not None


# --------------------------------------------------------------------------- #
# arq job: behavioral_baseline_sweep
# --------------------------------------------------------------------------- #


async def test_baseline_sweep_skips_and_warns_when_disabled(monkeypatch, caplog, db_session):
    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    # The stale-entity sweep half always runs (even disabled), so the job still
    # opens a session; give it the test session.
    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="btagent.scheduler.jobs"):
            result = await jobs.behavioral_baseline_sweep({})
        assert result["baselines_built"] == 0
        warnings = [r for r in caplog.records if "no telemetry source wired" in r.message]
        assert len(warnings) == 1
        assert "BTAGENT_BEHAVIORAL_SCHEDULE_ENABLED=true" in warnings[0].message
    finally:
        get_settings.cache_clear()


async def test_baseline_sweep_builds_baselines_when_enabled(monkeypatch, db_session):
    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    get_settings.cache_clear()
    try:
        result = await jobs.behavioral_baseline_sweep({})
        # B8: the sweep is multi-tenant — the mock-first CrowdStrike telemetry
        # spans two hosts, rebuilt once per org in the (shared-DB) org table.
        from btagent_backend.db.models import OrganizationRow

        org_count = len((await db_session.execute(select(OrganizationRow.id))).all())
        assert org_count >= 1
        assert result["baselines_built"] == 2 * org_count

        # A baseline landed for a mock host entity in the default org.
        prof = (
            await db_session.execute(
                select(BehavioralProfileRow)
                .join(
                    BehavioralEntityRow,
                    BehavioralProfileRow.entity_id == BehavioralEntityRow.id,
                )
                .where(
                    BehavioralEntityRow.org_id == DEFAULT_ORG_ID,
                    BehavioralEntityRow.canonical_id == "WS-JSMITH-PC",
                    BehavioralEntityRow.kind == EntityKind.HOST.value,
                )
            )
        ).scalar_one()
        assert prof.sample_size >= 1
        assert prof.frequency_map  # learned some process lineages
    finally:
        get_settings.cache_clear()
