"""Tests for Phase-B behavioral explainability + benign-label drift (#114).

Three slices, one per task:

* **most-similar normal example** — the nearest-exemplar lookup returns the
  entity's own baseline patterns ranked by similarity to the anomalous one,
  supplements them with peer baselines through the pgvector nearest-neighbour
  path, degrades cleanly on the SQLite unit-test DB instead of raising, and
  never crosses an org boundary.
* **explain view** — the assembled explanation carries the anomalous event, the
  baseline it was scored against, and only signals the detector actually
  produces (the unpersisted thresholds are reported as unavailable, not
  guessed), and the HTTP route is RBAC- and org-scoped.
* **benign re-evaluation** — the periodic pass flags entities whose
  previously-benign patterns have dropped out of the current baseline, clears
  the flag when they come back, isolates per-org/per-entity failures, and the
  arq job commits once.

Count-sensitive tests seed a dedicated per-test org (``generate_id("org")``) —
the backend suite shares one session-scoped in-memory SQLite whose committed
rows persist across tests.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from btagent_shared.hunt import behavioral as logic
from btagent_shared.types.behavioral import (
    EntityKind,
    ExemplarSource,
    IntentLabel,
    ProfileType,
)
from btagent_shared.utils.ids import generate_id
from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow
from btagent_backend.services import behavioral_service as svc

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def fresh_org(db_session):
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"Explain Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return oid


def _axis(index: int, *, dim: int = 8) -> list[float]:
    vec = [0.0] * dim
    vec[index] = 1.0
    return vec


async def _entity(db_session, org_id: str, canonical_id: str, *, kind=EntityKind.HOST):
    return await svc.upsert_entity(db_session, org_id=org_id, kind=kind, canonical_id=canonical_id)


async def _baseline(db_session, entity, *, pattern_keys, axis=0, profile_type=None):
    now = datetime.now(UTC)
    return await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=profile_type or ProfileType.CMDLINE_EMBEDDING,
        vectors=[_axis(axis)],
        pattern_keys=pattern_keys,
        window_start=now - timedelta(days=30),
        window_end=now,
    )


async def _outlier(db_session, entity, *, pattern_key, axis=4, event_id=None, excerpt=""):
    row = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id=event_id or generate_id("evt"),
        event_vector=_axis(axis),
        event_pattern_key=pattern_key,
        raw_event_excerpt=excerpt,
        emit_event=False,
    )
    assert row is not None
    return row


# --------------------------------------------------------------------------- #
# Pure logic: token-overlap ranking
# --------------------------------------------------------------------------- #


def test_pattern_similarity_is_token_overlap():
    # Shared child process, different parent -> 1 of 3 tokens in common.
    assert logic.pattern_similarity(
        "winword.exe>powershell.exe", "explorer.exe>powershell.exe"
    ) == pytest.approx(1 / 3)
    assert logic.pattern_similarity("a.exe>b.exe", "a.exe>b.exe") == 1.0
    assert logic.pattern_similarity("a.exe>b.exe", "c.exe>d.exe") == 0.0
    # Nothing to compare against is 0.0, never a divide-by-zero.
    assert logic.pattern_similarity("", "a.exe>b.exe") == 0.0


def test_nearest_patterns_ranks_by_similarity_then_count():
    freq = {
        "explorer.exe>powershell.exe": 3,
        "explorer.exe>cmd.exe": 40,
        "svchost.exe>rundll32.exe": 7,
    }
    ranked = logic.nearest_patterns(freq, "winword.exe>powershell.exe", k=3)
    # The lineage sharing powershell.exe wins despite being far less frequent.
    assert ranked[0][0] == "explorer.exe>powershell.exe"
    assert ranked[0][1] == 3
    assert ranked[0][2] > ranked[1][2]
    # Zero-similarity remainder falls back to most-frequent-first.
    assert [r[0] for r in ranked[1:]] == ["explorer.exe>cmd.exe", "svchost.exe>rundll32.exe"]


def test_nearest_patterns_without_a_key_falls_back_to_most_frequent():
    freq = {"a.exe>b.exe": 2, "c.exe>d.exe": 9}
    ranked = logic.nearest_patterns(freq, None, k=2)
    assert [r[0] for r in ranked] == ["c.exe>d.exe", "a.exe>b.exe"]
    assert {r[2] for r in ranked} == {0.0}


def test_nearest_patterns_is_bounded_and_deterministic():
    freq = {f"p{i}.exe>c.exe": 1 for i in range(20)}
    first = logic.nearest_patterns(freq, "p0.exe>c.exe", k=3)
    assert len(first) == 3
    assert logic.nearest_patterns(freq, "p0.exe>c.exe", k=3) == first
    assert logic.nearest_patterns(freq, "x", k=0) == []


# --------------------------------------------------------------------------- #
# Nearest baseline exemplars
# --------------------------------------------------------------------------- #


async def test_exemplars_return_the_entitys_most_similar_normal_patterns(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "EX-HOST-1")
    await _baseline(
        db_session,
        entity,
        pattern_keys=(
            ["explorer.exe>powershell.exe"] * 3
            + ["explorer.exe>cmd.exe"] * 40
            + ["svchost.exe>rundll32.exe"] * 7
        ),
    )
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    exemplars, notes = await svc.nearest_baseline_exemplars(
        db_session, outlier=outlier, limit=3, peer_limit=0
    )
    assert [e.source for e in exemplars] == [ExemplarSource.ENTITY_BASELINE] * 3
    assert exemplars[0].pattern_key == "explorer.exe>powershell.exe"
    assert exemplars[0].observation_count == 3
    # Rank is the entity's own frequency ranking, not the similarity ordering.
    assert exemplars[0].frequency_rank == 3
    assert exemplars[0].entity_canonical_id == "EX-HOST-1"
    # Token overlap is reported; the per-event embedding is not retained, so no
    # cosine distance is invented for an entity exemplar.
    assert exemplars[0].token_similarity == pytest.approx(1 / 3)
    assert exemplars[0].centroid_distance is None
    assert notes == []


async def test_exemplars_add_peer_baselines_through_the_vector_path(db_session, fresh_org):
    """The pgvector NN path supplies "entities like this one call X normal"."""
    entity = await _entity(db_session, fresh_org, "EX-SELF")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"], axis=0)
    peer = await _entity(db_session, fresh_org, "EX-PEER")
    await _baseline(db_session, peer, pattern_keys=["explorer.exe>msiexec.exe"] * 4, axis=0)
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    exemplars, _ = await svc.nearest_baseline_exemplars(
        db_session, outlier=outlier, limit=1, peer_limit=2
    )
    peers = [e for e in exemplars if e.source == ExemplarSource.PEER_BASELINE]
    assert [e.entity_canonical_id for e in peers] == ["EX-PEER"]
    assert peers[0].pattern_key == "explorer.exe>msiexec.exe"
    # Peer ranking is the real pgvector cosine distance, not a token score.
    assert peers[0].centroid_distance == pytest.approx(0.0, abs=1e-6)
    assert peers[0].token_similarity is None
    # The entity's own baseline is never returned as its own peer.
    assert entity.id not in {e.entity_id for e in peers}


async def test_exemplars_fall_back_cleanly_on_sqlite(db_session, fresh_org):
    """pgvector operators don't exist on SQLite — degrade, never raise."""
    assert svc._is_postgres(db_session) is False

    entity = await _entity(db_session, fresh_org, "EX-SQLITE")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"], axis=1)
    peer = await _entity(db_session, fresh_org, "EX-SQLITE-PEER")
    await _baseline(db_session, peer, pattern_keys=["explorer.exe>wscript.exe"], axis=1)
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    exemplars, _ = await svc.nearest_baseline_exemplars(db_session, outlier=outlier)
    assert {e.source for e in exemplars} == {
        ExemplarSource.ENTITY_BASELINE,
        ExemplarSource.PEER_BASELINE,
    }


async def test_exemplars_survive_a_forced_vector_query_error(
    db_session, fresh_org, monkeypatch, caplog
):
    """Force the PG path on SQLite: the failure degrades to the in-Python scan."""
    caplog.set_level(logging.WARNING, logger="btagent.services.behavioral")
    entity = await _entity(db_session, fresh_org, "EX-DEGRADE")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"], axis=2)
    peer = await _entity(db_session, fresh_org, "EX-DEGRADE-PEER")
    await _baseline(db_session, peer, pattern_keys=["explorer.exe>reg.exe"], axis=2)
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    monkeypatch.setattr(svc, "_is_postgres", lambda session: True)
    exemplars, _ = await svc.nearest_baseline_exemplars(db_session, outlier=outlier)

    assert "vector query failed" in caplog.text
    peers = [e for e in exemplars if e.source == ExemplarSource.PEER_BASELINE]
    assert [e.entity_canonical_id for e in peers] == ["EX-DEGRADE-PEER"]


async def test_exemplar_peer_search_is_org_scoped(db_session):
    """A baseline in another tenant is never shown as "normal" here."""
    org_a, org_b = generate_id("org"), generate_id("org")
    for oid in (org_a, org_b):
        db_session.add(OrganizationRow(id=oid, name=f"Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()

    entity = await _entity(db_session, org_a, "EX-TENANT-A")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"], axis=0)
    other = await _entity(db_session, org_b, "EX-TENANT-B")
    await _baseline(db_session, other, pattern_keys=["evil.exe>mimikatz.exe"] * 9, axis=0)
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    exemplars, _ = await svc.nearest_baseline_exemplars(db_session, outlier=outlier, peer_limit=5)
    assert "evil.exe>mimikatz.exe" not in {e.pattern_key for e in exemplars}
    assert other.id not in {e.entity_id for e in exemplars}


async def test_exemplars_report_a_missing_baseline_instead_of_raising(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "EX-NO-BASELINE")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    # A different profile type has no baseline at all.
    outlier.profile_type = ProfileType.NETWORK_EGRESS_PROFILE.value
    await db_session.flush()

    exemplars, notes = await svc.nearest_baseline_exemplars(db_session, outlier=outlier)
    assert exemplars == []
    assert any("No baseline window exists" in n for n in notes)


# --------------------------------------------------------------------------- #
# explain_outlier
# --------------------------------------------------------------------------- #


async def test_explain_assembles_event_baseline_exemplars_and_signals(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "EXPLAIN-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>powershell.exe"] * 5)
    outlier = await _outlier(
        db_session,
        entity,
        pattern_key="winword.exe>powershell.exe",
        excerpt="winword.exe>powershell.exe: powershell -enc <b64>",
    )

    explanation = await svc.explain_outlier(db_session, outlier_id=outlier.id)

    assert explanation.outlier.id == outlier.id
    assert explanation.entity_canonical_id == "EXPLAIN-HOST"
    assert explanation.entity_kind == EntityKind.HOST
    assert explanation.anomalous_event.endswith("powershell -enc <b64>")
    assert explanation.event_pattern_key == "winword.exe>powershell.exe"
    assert explanation.baseline is not None
    assert explanation.baseline.sample_size == 5
    assert explanation.baseline.has_centroid is True
    assert explanation.exemplars[0].pattern_key == "explorer.exe>powershell.exe"

    signals = {s.key: s for s in explanation.signals}
    # The detector's own numbers, verbatim.
    assert signals["cosine_distance"].value == f"{outlier.cosine_distance:.3f}"
    assert signals["frequency_rank"].value == str(outlier.frequency_rank)
    assert signals["process_lineage"].value == "winword.exe>powershell.exe"
    assert signals["baseline_sample_size"].value == "5"
    # Nothing invented: the un-persisted thresholds are declared unavailable.
    assert signals["frequency_floor"].available is False
    assert signals["frequency_floor"].value is None
    assert signals["intent"].available is False
    # The exemplar ranking method is disclosed rather than implied.
    assert any("token overlap" in n for n in explanation.notes)


async def test_explain_says_so_when_there_is_no_baseline(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "EXPLAIN-NOBASE")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")
    outlier.profile_type = ProfileType.IDENTITY_ACTION_SEQUENCE.value
    await db_session.flush()

    explanation = await svc.explain_outlier(db_session, outlier_id=outlier.id)
    assert explanation.baseline is None
    assert explanation.exemplars == []
    signals = {s.key: s for s in explanation.signals}
    assert signals["baseline_sample_size"].available is False


async def test_explain_surfaces_an_intent_verdict_when_one_exists(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "EXPLAIN-INTENT")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")
    await svc.set_intent(
        db_session,
        outlier_id=outlier.id,
        label=IntentLabel.SUSPICIOUS,
        rationale="encoded command from an office parent",
    )

    explanation = await svc.explain_outlier(db_session, outlier_id=outlier.id)
    signals = {s.key: s for s in explanation.signals}
    assert signals["intent"].available is True
    assert signals["intent"].value == "suspicious"
    assert "encoded command" in signals["intent"].detail


async def test_explain_raises_for_a_missing_outlier(db_session):
    with pytest.raises(ValueError, match="not found"):
        await svc.explain_outlier(db_session, outlier_id="bout_does_not_exist")


# --------------------------------------------------------------------------- #
# Explain route: RBAC + org scoping
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture()
async def seeded_outlier(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-EXPLAIN-API"
    )
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>powershell.exe"] * 4)
    row = await _outlier(
        db_session,
        entity,
        pattern_key="winword.exe>powershell.exe",
        excerpt="winword.exe -> powershell -enc <b64>",
    )
    await db_session.commit()
    return row


async def test_explain_route_returns_the_panel_payload(client, analyst_token, seeded_outlier):
    resp = await client.get(
        f"/api/v1/behavioral/outliers/{seeded_outlier.id}/explain",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["outlier"]["id"] == seeded_outlier.id
    assert body["entity_canonical_id"] == "WS-EXPLAIN-API"
    assert body["exemplars"][0]["pattern_key"] == "explorer.exe>powershell.exe"
    assert {s["key"] for s in body["signals"]} >= {
        "cosine_distance",
        "frequency_rank",
        "process_lineage",
        "frequency_floor",
    }


async def test_explain_route_requires_auth(client, seeded_outlier):
    resp = await client.get(f"/api/v1/behavioral/outliers/{seeded_outlier.id}/explain")
    assert resp.status_code in (401, 403)


async def test_explain_route_is_org_scoped(client, db_session, analyst_token):
    """An outlier in another tenant 404s rather than explaining itself."""
    other_org = generate_id("org")
    db_session.add(
        OrganizationRow(id=other_org, name="Other Explain Org", created_at=datetime.now(UTC))
    )
    await db_session.commit()

    entity = await _entity(db_session, other_org, "OTHER-TENANT-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    outlier = await _outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/behavioral/outliers/{outlier.id}/explain",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


async def test_explain_route_404s_for_an_unknown_outlier(client, analyst_token):
    resp = await client.get(
        "/api/v1/behavioral/outliers/bout_nope/explain", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Benign-label re-evaluation
# --------------------------------------------------------------------------- #


async def _benign_outlier(db_session, entity, *, pattern_key):
    row = await _outlier(db_session, entity, pattern_key=pattern_key)
    await svc.set_intent(
        db_session, outlier_id=row.id, label=IntentLabel.BENIGN, rationale="admin scripting"
    )
    return row


async def test_reeval_flags_an_entity_whose_benign_pattern_left_the_baseline(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "DRIFT-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    # A newer baseline window that no longer contains the cleared pattern.
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[_axis(0)],
        pattern_keys=["explorer.exe>cmd.exe"] * 12,
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(minutes=1),
    )
    await db_session.flush()

    result = await svc.reevaluate_benign_labels(db_session, org_id=fresh_org)
    assert result.entities_flagged == 1
    assert entity.id in result.flagged_entity_ids
    flag = entity.enrichment[svc.BENIGN_DRIFT_KEY]
    assert flag["drifted_count"] == 1
    assert "pattern absent" in flag["reason"]
    # Non-destructive: the analyst's verdict itself is untouched.
    assert result.outliers_checked == 1


async def test_reeval_leaves_a_still_normal_benign_label_alone(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "STABLE-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    benign = await _benign_outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    # Fold the benign pattern into the baseline (the closed-loop feedback path),
    # so the current baseline still considers it normal.
    await svc.feedback_benign(db_session, outlier_id=benign.id)

    result = await svc.reevaluate_benign_labels(db_session, org_id=fresh_org)
    assert result.entities_flagged == 0
    assert svc.BENIGN_DRIFT_KEY not in (entity.enrichment or {})


async def test_reeval_clears_a_stale_flag_when_the_pattern_returns(db_session, fresh_org):
    entity = await _entity(db_session, fresh_org, "RECOVER-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    benign = await _benign_outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")

    first = await svc.reevaluate_benign_labels(db_session, org_id=fresh_org)
    assert first.entities_flagged == 1
    assert svc.BENIGN_DRIFT_KEY in entity.enrichment

    await svc.feedback_benign(db_session, outlier_id=benign.id)
    second = await svc.reevaluate_benign_labels(db_session, org_id=fresh_org)
    assert second.entities_cleared == 1
    assert svc.BENIGN_DRIFT_KEY not in entity.enrichment


async def test_reeval_flag_survives_the_entity_being_observed_again(db_session, fresh_org):
    """``upsert_entity`` merges enrichment, so re-observation can't erase it."""
    entity = await _entity(db_session, fresh_org, "REOBSERVED-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")
    await svc.reevaluate_benign_labels(db_session, org_id=fresh_org)

    again = await _entity(db_session, fresh_org, "REOBSERVED-HOST")
    assert again.id == entity.id
    assert svc.BENIGN_DRIFT_KEY in again.enrichment


async def test_reeval_is_org_scoped(db_session):
    org_a, org_b = generate_id("org"), generate_id("org")
    for oid in (org_a, org_b):
        db_session.add(OrganizationRow(id=oid, name=f"Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()

    a_entity = await _entity(db_session, org_a, "REEVAL-A")
    await _baseline(db_session, a_entity, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, a_entity, pattern_key="winword.exe>powershell.exe")

    b_entity = await _entity(db_session, org_b, "REEVAL-B")
    await _baseline(db_session, b_entity, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, b_entity, pattern_key="winword.exe>powershell.exe")

    result = await svc.reevaluate_benign_labels(db_session, org_id=org_a)
    assert result.flagged_entity_ids == [a_entity.id]
    assert svc.BENIGN_DRIFT_KEY not in (b_entity.enrichment or {})


async def test_reeval_all_orgs_isolates_a_failing_tenant(db_session, monkeypatch, caplog):
    """One org blowing up is counted and skipped, not fatal to the sweep."""
    caplog.set_level(logging.ERROR, logger="btagent.services.behavioral")
    org_bad, org_good = generate_id("org"), generate_id("org")
    for oid in (org_bad, org_good):
        db_session.add(OrganizationRow(id=oid, name=f"Org {oid}", created_at=datetime.now(UTC)))
    await db_session.commit()

    for oid, name in ((org_bad, "SWEEP-BAD"), (org_good, "SWEEP-GOOD")):
        entity = await _entity(db_session, oid, name)
        await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
        await _benign_outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")
    await db_session.flush()

    real = svc.reevaluate_benign_labels

    async def _flaky(db, *, org_id, **kwargs):
        if org_id == org_bad:
            raise RuntimeError("boom")
        return await real(db, org_id=org_id, **kwargs)

    monkeypatch.setattr(svc, "reevaluate_benign_labels", _flaky)
    totals = await svc.reevaluate_benign_labels_all_orgs(db_session)

    assert totals.failures >= 1
    assert totals.orgs >= 1
    # The healthy tenant was still processed.
    good_entity = (
        await svc.upsert_entity(
            db_session, org_id=org_good, kind=EntityKind.HOST, canonical_id="SWEEP-GOOD"
        )
    ).enrichment
    assert svc.BENIGN_DRIFT_KEY in good_entity


async def test_reeval_tolerates_a_failing_entity_within_an_org(db_session, fresh_org, monkeypatch):
    """A per-entity failure is counted, and the other entities still get swept."""
    boom = await _entity(db_session, fresh_org, "ENTITY-BOOM")
    await _baseline(db_session, boom, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, boom, pattern_key="winword.exe>powershell.exe")
    ok = await _entity(db_session, fresh_org, "ENTITY-OK")
    await _baseline(db_session, ok, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, ok, pattern_key="winword.exe>wscript.exe")
    await db_session.flush()

    real_latest = svc._get_latest_profile

    async def _flaky(db, *, entity_id, profile_type):
        if entity_id == boom.id:
            raise RuntimeError("profile load exploded")
        return await real_latest(db, entity_id=entity_id, profile_type=profile_type)

    monkeypatch.setattr(svc, "_get_latest_profile", _flaky)
    result = await svc.reevaluate_benign_labels(db_session, org_id=fresh_org)

    assert result.failures == 1
    assert result.flagged_entity_ids == [ok.id]


async def test_benign_reeval_job_commits_once(db_session, fresh_org, monkeypatch):
    """The arq cron is a thin shell: sweep every org, commit, return counts."""
    from contextlib import asynccontextmanager

    from btagent_backend.scheduler import jobs

    entity = await _entity(db_session, fresh_org, "JOB-DRIFT-HOST")
    await _baseline(db_session, entity, pattern_keys=["explorer.exe>cmd.exe"])
    await _benign_outlier(db_session, entity, pattern_key="winword.exe>powershell.exe")
    await db_session.commit()

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    counts = await jobs.behavioral_benign_reeval_sweep({})

    assert counts["entities_flagged"] >= 1
    assert counts["orgs"] >= 1
    assert svc.BENIGN_DRIFT_KEY in entity.enrichment


def test_benign_reeval_job_is_registered_on_the_worker():
    from btagent_backend.scheduler import jobs
    from btagent_backend.scheduler.worker import WorkerSettings

    assert jobs.behavioral_benign_reeval_sweep in WorkerSettings.functions
    crons = [c for c in WorkerSettings.cron_jobs if "benign_reeval" in c.name]
    assert len(crons) == 1
    # ``unique=True`` — one tick across worker replicas, like the other sweeps.
    assert crons[0].unique is True
