"""Tests for the Behavioral Hunter service (#114).

Covers the persistence + detection wiring against the in-memory SQLite DB:
entity upsert, baseline build, outlier detection, intent setting,
promotion into the #119 store, and the benign-feedback closed loop.
"""

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.types.behavioral import EntityKind, IntentLabel, ProfileType

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_behavioral import BehavioralOutlierRow
from btagent_backend.services import behavioral_service as svc

# --- entity upsert ---


async def test_upsert_entity_creates_and_then_updates(db_session):
    e1 = await svc.upsert_entity(
        db_session,
        org_id=DEFAULT_ORG_ID,
        kind=EntityKind.USER,
        canonical_id="alice@example.com",
        enrichment={"role": "analyst"},
    )
    assert e1.id.startswith("bent_")
    first_seen = e1.first_seen
    last_seen_initial = e1.last_seen

    # Same key -> updates last_seen + merges enrichment, no new row.
    e2 = await svc.upsert_entity(
        db_session,
        org_id=DEFAULT_ORG_ID,
        kind=EntityKind.USER,
        canonical_id="alice@example.com",
        enrichment={"dept": "secops"},
    )
    assert e2.id == e1.id
    assert e2.first_seen == first_seen
    assert e2.last_seen >= last_seen_initial
    assert e2.enrichment == {"role": "analyst", "dept": "secops"}


# --- baseline build ---


async def test_build_baseline_computes_centroid_and_freq_map(db_session):
    entity = await svc.upsert_entity(
        db_session,
        org_id=DEFAULT_ORG_ID,
        kind=EntityKind.HOST,
        canonical_id="WS-1",
    )
    now = datetime.now(UTC)
    profile = await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0], [1.0, 0.0], [0.0, 1.0]],
        pattern_keys=["pwsh.exe", "pwsh.exe", "cmd.exe"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    # Centroid is the elementwise mean: ([1+1+0]/3, [0+0+1]/3)
    assert profile.centroid == pytest.approx([2 / 3, 1 / 3])
    assert profile.frequency_map == {"pwsh.exe": 2, "cmd.exe": 1}
    assert profile.pattern_count == 2
    assert profile.sample_size == 3


async def test_build_baseline_rejects_inconsistent_vector_lengths(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-2"
    )
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="share length"):
        await svc.build_baseline(
            db_session,
            entity=entity,
            profile_type=ProfileType.CMDLINE_EMBEDDING,
            vectors=[[1.0, 0.0], [1.0]],
            pattern_keys=[],
            window_start=now - timedelta(days=1),
            window_end=now,
        )


# --- detect_outlier ---


async def test_detect_outlier_returns_none_without_baseline(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-3"
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_x",
        event_vector=[0.0, 1.0],
        event_pattern_key="pwsh.exe -enc ...",
    )
    assert out is None


async def test_detect_outlier_returns_none_when_near_centroid(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-4"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common_pattern"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    # near-identical to centroid; pattern is rare but distance gates the call
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_y",
        event_vector=[0.99, 0.01],
        event_pattern_key="brand_new",
    )
    assert out is None


async def test_detect_outlier_persists_when_far_and_rare(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-5"
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
        event_id="evt_enc_pwsh",
        event_vector=[0.0, 1.0],  # orthogonal -> distance ~1.0
        event_pattern_key="encoded_pwsh_payload",
        raw_event_excerpt="powershell -enc <b64>",
    )
    assert out is not None
    assert out.id.startswith("bout_")
    assert out.entity_id == entity.id
    assert out.event_id == "evt_enc_pwsh"
    assert out.cosine_distance == pytest.approx(1.0)
    assert out.frequency_rank == 0
    assert out.raw_event_excerpt == "powershell -enc <b64>"
    assert out.intent_label is None  # LLM hasn't classified yet


# --- set_intent ---


async def test_set_intent_updates_label_and_rationale(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-6"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_z",
        event_vector=[0.0, 1.0],
        event_pattern_key="rare",
    )
    assert out is not None
    updated = await svc.set_intent(
        db_session,
        outlier_id=out.id,
        label=IntentLabel.SUSPICIOUS,
        rationale="encoded payload + parent-child anomaly",
    )
    assert updated.intent_label == "suspicious"
    assert "encoded payload" in updated.intent_rationale


# --- promotion to #119 ---


async def test_promote_outlier_lands_in_hunt_findings_store(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-PROMOTE"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_promote",
        event_vector=[0.0, 1.0],
        event_pattern_key="rare",
    )
    assert out is not None
    await svc.set_intent(
        db_session,
        outlier_id=out.id,
        label=IntentLabel.MALICIOUS,
        rationale="confirmed C2 beacon",
    )

    finding_id = await svc.promote_outlier(
        db_session, outlier_id=out.id, technique_ids=["T1059.001"]
    )
    assert finding_id.startswith("hfnd_")

    refreshed = await db_session.get(BehavioralOutlierRow, out.id)
    assert refreshed.promoted_to_finding_id == finding_id


# --- benign-feedback closed loop ---


async def test_feedback_benign_bumps_frequency_in_baseline(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-FB"
    )
    now = datetime.now(UTC)
    profile = await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    initial_sample = profile.sample_size
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_known_safe",
        event_vector=[0.0, 1.0],
        event_pattern_key="rare_but_safe",
    )
    assert out is not None
    await svc.set_intent(
        db_session,
        outlier_id=out.id,
        label=IntentLabel.BENIGN,
        rationale="admin tooling",
    )

    updated = await svc.feedback_benign(db_session, outlier_id=out.id)
    assert "evt_known_safe" in updated.frequency_map
    assert updated.sample_size == initial_sample + 1


async def test_feedback_benign_refuses_non_benign(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-FB2"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_susp",
        event_vector=[0.0, 1.0],
        event_pattern_key="rare",
    )
    assert out is not None
    await svc.set_intent(
        db_session,
        outlier_id=out.id,
        label=IntentLabel.SUSPICIOUS,
        rationale="possible LotL",
    )
    with pytest.raises(ValueError, match="feedback_benign called"):
        await svc.feedback_benign(db_session, outlier_id=out.id)


# --- stale entities ---


async def test_stale_entities_returns_only_unseen(db_session):
    now = datetime.now(UTC)
    fresh = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.USER, canonical_id="recent"
    )
    stale = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.USER, canonical_id="abandoned"
    )
    # backdate the stale one
    stale.last_seen = now - timedelta(days=60)
    await db_session.flush()

    result = await svc.stale_entities(db_session, now=now, stale_after=timedelta(days=30))
    stale_ids = {e.id for e in result}
    assert stale.id in stale_ids
    assert fresh.id not in stale_ids


async def test_promote_outlier_truncates_long_title(db_session):
    # A long canonical_id must not blow past RecordFindingRequest.title (300).
    long_id = "svc-" + "a" * 500
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.SERVICE_PRINCIPAL, canonical_id=long_id
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_long",
        event_vector=[0.0, 1.0],
        event_pattern_key="rare",
    )
    assert out is not None
    # Must not raise a ValidationError on the 300-char title cap.
    finding_id = await svc.promote_outlier(db_session, outlier_id=out.id)
    assert finding_id.startswith("hfnd_")
