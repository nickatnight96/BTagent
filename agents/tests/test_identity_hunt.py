"""Golden tests for the Identity Hunt Agent (#116) — connector-independent slice.

All tests are:
- Deterministic (fixed fixture timestamps, no randomness)
- Free of network / DB / LLM calls
- Testing both the detectors themselves AND the RecordFindingRequest contract

Test coverage:
  OAUTH TOKEN REPLAY
  - token_replay_flagged              positive case (2 ASNs, 18 min)
  - clean_token_not_flagged           negative (same ASN)

  DORMANT APP REACTIVATION
  - dormant_app_flagged               positive (100 days idle)
  - active_app_not_flagged            negative (10 days idle)
  - dormant_app_finding_valid         positive -> valid RecordFindingRequest

  IMPOSSIBLE TRAVEL
  - impossible_travel_flagged         positive (London->NY in 5 min)
  - possible_travel_not_flagged       negative (London->NY in 8 hours)

  SERVICE PRINCIPAL CREDENTIAL ADDITION
  - sp_cred_addition_flagged          positive (app_id populated)
  - non_sp_cred_not_flagged           negative (regular user, no app_id)

  FEDERATION TRUST MODIFICATION
  - federation_trust_flagged          always-flag
  - federation_trust_severity         must be critical

  MFA FATIGUE
  - mfa_fatigue_flagged               positive (4 denials + approve)
  - mfa_clean_not_flagged             negative (2 denials, below threshold)

  FINDING CONTRACT
  - token_replay_to_record_finding    RecordFindingRequest.source == identity
  - dormant_app_to_record_finding     RecordFindingRequest.domain == identity
  - all_findings_have_technique_ids   every result has >=1 technique

  RUN_ALL
  - run_all_combined_fixture          multi-source fixture; all 6 detectors fire

  OAUTH GRANT GRAPH
  - build_grant_graph_structure       graph keys and scope list
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.hunt.identity import (
    build_grant_graph,
    detect_dormant_app_reactivation,
    detect_federation_trust_modification,
    detect_impossible_travel,
    detect_mfa_fatigue,
    detect_oauth_token_replay,
    detect_service_principal_credential_addition,
    results_to_findings,
    run_all_detectors,
    to_record_finding_request,
)
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.identity_hunt import IdentityProvider, OAuthConsentType, OAuthGrant

from tests.fixtures.identity.fixture_events import (
    active_grant_and_events,
    clean_token_events,
    dormant_grant_and_events,
    federation_trust_modification_events,
    impossible_travel_events,
    mfa_clean_events,
    mfa_fatigue_events,
    non_sp_credential_addition_events,
    possible_travel_events,
    sp_credential_addition_events,
    token_replay_events,
)

# ── OAuth token replay ─────────────────────────────────────────────────────


def test_token_replay_flagged() -> None:
    """A session_id appearing from 2 ASNs in 18 min should be flagged."""
    events = token_replay_events()
    results = detect_oauth_token_replay(events, window_minutes=30, min_asn_count=2)
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "identity.oauth_token_replay"
    assert "AS15169" in r.evidence["distinct_asns"]
    assert "AS8075" in r.evidence["distinct_asns"]
    assert r.severity == "high"
    assert r.confidence > 0.5


def test_clean_token_not_flagged() -> None:
    """Same ASN — should not produce a replay finding."""
    results = detect_oauth_token_replay(clean_token_events(), min_asn_count=2)
    assert results == []


# ── Dormant app reactivation ───────────────────────────────────────────────


def test_dormant_app_flagged() -> None:
    """An OAuth app idle for 100 days then used should be flagged."""
    grants, events = dormant_grant_and_events()
    results = detect_dormant_app_reactivation(grants, events, idle_days=90)
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "identity.dormant_app_reactivation"
    assert r.evidence["app_id"] == "app_FORGOTTEN_SAAS_001"
    assert r.evidence["idle_days"] >= 90
    assert r.severity == "high"


def test_active_app_not_flagged() -> None:
    """An OAuth app used 10 days ago should not flag."""
    grants, events = active_grant_and_events()
    results = detect_dormant_app_reactivation(grants, events, idle_days=90)
    assert results == []


def test_dormant_app_finding_valid() -> None:
    """The dormant-app result must produce a valid RecordFindingRequest."""
    grants, events = dormant_grant_and_events()
    results = detect_dormant_app_reactivation(grants, events, idle_days=90)
    assert results
    req = to_record_finding_request(results[0])
    # Contract checks
    assert req.source == HuntSource.IDENTITY
    assert req.domain == HuntDomain.IDENTITY
    assert req.title
    assert req.technique_ids  # at least one technique
    assert req.entities  # at least one entity


# ── Impossible travel ──────────────────────────────────────────────────────


def test_impossible_travel_flagged() -> None:
    """London->NY in 5 minutes (>50000 km/h) must be flagged."""
    results = detect_impossible_travel(impossible_travel_events(), min_speed_kmh=900)
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "identity.impossible_travel"
    assert r.evidence["speed_kmh"] > 900
    assert r.evidence["distance_km"] > 5000
    assert r.severity == "high"
    assert r.confidence >= 0.9


def test_possible_travel_not_flagged() -> None:
    """London->NY in 8 hours (~700 km/h) is below threshold — no flag."""
    results = detect_impossible_travel(possible_travel_events(), min_speed_kmh=900)
    assert results == []


# ── Service principal credential addition ─────────────────────────────────


def test_sp_cred_addition_flagged() -> None:
    """CREDENTIAL_ADDED with app_id populated should flag."""
    results = detect_service_principal_credential_addition(sp_credential_addition_events())
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "identity.service_principal_credential_addition"
    assert r.entity_kind == "service_principal"
    assert "T1098.001" in r.technique_ids
    assert r.severity == "high"


def test_non_sp_cred_not_flagged() -> None:
    """CREDENTIAL_ADDED for a regular user UPN without app_id should not flag."""
    results = detect_service_principal_credential_addition(non_sp_credential_addition_events())
    assert results == []


# ── Federation trust modification ─────────────────────────────────────────


def test_federation_trust_flagged() -> None:
    """Any FEDERATION_TRUST_MODIFIED event must produce a finding."""
    results = detect_federation_trust_modification(federation_trust_modification_events())
    assert len(results) == 1
    assert results[0].rule_id == "identity.federation_trust_modification"


def test_federation_trust_severity() -> None:
    """Federation trust modification is always critical severity."""
    results = detect_federation_trust_modification(federation_trust_modification_events())
    assert results[0].severity == "critical"
    assert "T1484.002" in results[0].technique_ids


# ── MFA fatigue ───────────────────────────────────────────────────────────


def test_mfa_fatigue_flagged() -> None:
    """4 denials + approve within 8 minutes should flag MFA fatigue."""
    results = detect_mfa_fatigue(mfa_fatigue_events(), denial_threshold=3, window_minutes=10)
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "identity.mfa_fatigue"
    assert r.evidence["denial_count"] == 4
    assert "T1621" in r.technique_ids
    assert r.severity == "high"


def test_mfa_clean_not_flagged() -> None:
    """Only 2 denials before approve (below threshold of 3) — should not flag."""
    results = detect_mfa_fatigue(mfa_clean_events(), denial_threshold=3, window_minutes=10)
    assert results == []


# ── Finding contract (RecordFindingRequest) ────────────────────────────────


def test_token_replay_to_record_finding() -> None:
    """Token replay result must emit source=identity."""
    results = detect_oauth_token_replay(token_replay_events())
    assert results
    req = to_record_finding_request(results[0])
    assert req.source == HuntSource.IDENTITY
    assert req.domain == HuntDomain.IDENTITY
    assert req.title
    assert 0.0 <= req.confidence <= 1.0


def test_dormant_app_to_record_finding() -> None:
    """Dormant app result must emit domain=identity and carry evidence."""
    grants, events = dormant_grant_and_events()
    results = detect_dormant_app_reactivation(grants, events)
    assert results
    req = to_record_finding_request(results[0])
    assert req.domain == HuntDomain.IDENTITY
    assert "rule_id" in req.evidence
    assert "detection_id" in req.evidence


def test_all_findings_have_technique_ids() -> None:
    """Every detection result from every detector must carry at least one ATT&CK technique."""
    grants_d, events_d = dormant_grant_and_events()
    all_events = (
        token_replay_events()
        + events_d
        + impossible_travel_events()
        + sp_credential_addition_events()
        + federation_trust_modification_events()
        + mfa_fatigue_events()
    )
    all_grants = grants_d
    results = run_all_detectors(all_events, all_grants)
    assert results, "Expected at least one detection across all fixtures"
    for r in results:
        assert r.technique_ids, f"Detection {r.rule_id} has no technique_ids"
        for tid in r.technique_ids:
            assert tid.startswith("T"), f"Technique ID {tid!r} does not start with 'T'"


# ── run_all_detectors ──────────────────────────────────────────────────────


def test_run_all_combined_fixture() -> None:
    """run_all_detectors on combined fixture must fire all 6 detectors."""
    grants_d, events_d = dormant_grant_and_events()
    all_events = (
        token_replay_events()
        + events_d
        + impossible_travel_events()
        + sp_credential_addition_events()
        + federation_trust_modification_events()
        + mfa_fatigue_events()
    )
    results = run_all_detectors(all_events, grants_d)

    rule_ids_fired = {r.rule_id for r in results}
    expected = {
        "identity.oauth_token_replay",
        "identity.dormant_app_reactivation",
        "identity.impossible_travel",
        "identity.service_principal_credential_addition",
        "identity.federation_trust_modification",
        "identity.mfa_fatigue",
    }
    assert expected == rule_ids_fired, (
        f"Not all detectors fired.\nExpected: {sorted(expected)}\nGot: {sorted(rule_ids_fired)}"
    )

    # All results should convert to valid RecordFindingRequests without raising
    findings = results_to_findings(results)
    assert len(findings) == len(results)
    for f in findings:
        assert f.source == HuntSource.IDENTITY
        assert f.domain == HuntDomain.IDENTITY


def test_run_all_dedup() -> None:
    """Duplicate events should not produce duplicate detection_ids in run_all."""
    events = token_replay_events() + token_replay_events()  # doubled
    results = run_all_detectors(events)
    detection_ids = [r.detection_id for r in results]
    assert len(detection_ids) == len(set(detection_ids)), "Duplicate detection_ids found"


def test_run_all_empty_events() -> None:
    """Empty event list should produce no results (no crash)."""
    results = run_all_detectors([], [])
    assert results == []


# ── OAuth grant graph ──────────────────────────────────────────────────────


def test_build_grant_graph_structure() -> None:
    """build_grant_graph returns a nested {principal: {app: {...}}} dict."""
    grants, _ = dormant_grant_and_events()
    graph = build_grant_graph(grants)
    assert "alice@corp.example.com" in graph
    app_entry = graph["alice@corp.example.com"]["app_FORGOTTEN_SAAS_001"]
    assert "Mail.Read" in app_entry["scopes"]
    assert app_entry["consent_type"] == "user"
    assert app_entry["last_used"] is not None  # was set in fixture


def test_build_grant_graph_excludes_revoked() -> None:
    """Revoked grants (revoked_at set) must not appear in the graph."""
    revoked_grant = OAuthGrant(
        id="grant_REVOKED_001",
        org_id="org_01FIXTURE",
        app_id="app_REVOKED_001",
        principal_id="zach@corp.example.com",
        provider=IdentityProvider.ENTRA,
        scopes=["Mail.Read"],
        consent_type=OAuthConsentType.USER,
        granted_at=datetime(2026, 1, 1, tzinfo=UTC),
        revoked_at=datetime(2026, 3, 1, tzinfo=UTC),
    )
    graph = build_grant_graph([revoked_grant])
    assert graph == {}
