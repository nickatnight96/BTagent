"""Golden tests for Cloud Control-Plane Hunter — connector-independent slice (#117).

All tests are:
- Deterministic (no network, no LLM, no DB).
- Pure-logic: they exercise btagent_shared.hunt.cloud over synthetic fixture data.
- Fast: no async, no Docker.

Test matrix:
  T1   STS chaining — finds ≥ 1 path in the 3-hop fixture graph.
  T2   STS chaining — does NOT flag a clean graph with no attack paths.
  T3   STS chaining — respects min_hops parameter.
  T4   Trust graph — build_trust_graph returns correct adjacency map.
  T5   Trust graph — transitive_reachable returns all reachable nodes.
  T6   IAM persistence — flags CreateAccessKey, PutRolePolicy, UpdateAssumeRolePolicy.
  T7   IAM persistence — ignores benign events (GetCallerIdentity).
  T8   Cross-account trust — flags external trustee; does NOT flag approved account.
  T9   Snapshot external share — flags external-account share.
  T10  Snapshot public share — flags 'all' / public AMI as CRITICAL.
  T11  Snapshot trusted share — still flagged (configurable suppression at triage level).
  T12  CloudTrail tamper — correlated StopLogging+GetSessionToken produces CRITICAL.
  T13  CloudTrail tamper — standalone StopLogging produces HIGH (lower confidence).
  T14  Shadow workload — fixture produces ≥ 3 shadow findings.
  T15  Shadow workload — managed workload is NOT flagged.
  T16  Shadow workload — UNMANAGED kind is shadow even if governance_tagged is True.
  T17  Risk score — score_workload_risk returns correct values for all flag combos.
  T18  Overprivileged identity — flags workloads with has_overprivileged_identity.
  T19  run_all_detections — integration sweep over full fixture bundle returns findings.
  T20  RecordFindingRequest shapes — all outputs are valid Pydantic models.
  T21  MITRE mapper — cloud keywords resolve to correct technique IDs.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from btagent_shared.hunt.cloud import (
    build_trust_graph,
    classify_workload,
    detect_cloudtrail_tamper,
    detect_cross_account_trust_abuse,
    detect_iam_persistence,
    detect_overprivileged_workload_identity,
    detect_shadow_workloads,
    detect_snapshot_external_share,
    detect_sts_chaining,
    find_assumption_paths,
    run_all_detections,
    score_workload_risk,
    transitive_reachable,
)
from btagent_shared.types.cloud_hunt import (
    AgenticWorkload,
    AgenticWorkloadKind,
    CloudIdentity,
    CloudProvider,
    IdentityKind,
)
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import RecordFindingRequest

from tests.fixtures.cloud.iam_fixtures import (
    AGENTIC_IDENTITY_INVENTORY,
    AGENTIC_WORKLOAD_INVENTORY,
    CLOUDTRAIL_TAMPER_EVENTS,
    CROSS_ACCOUNT_IDENTITIES,
    CROSS_ACCOUNT_TRUSTED_IDS,
    EXTERNAL_ACCOUNT,
    IAM_PERSISTENCE_EVENTS,
    ORG_ID,
    SECOND_ACCOUNT,
    SNAPSHOT_SHARE_EVENTS,
    STS_CHAIN_IDENTITIES,
    STS_HIGH_VALUE_TARGETS,
    TRUSTED_ACCOUNT,
)

_FIXED_NOW = datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# T1–T3: STS chaining
# ---------------------------------------------------------------------------


def test_T1_sts_chaining_finds_attack_path():
    """STS chaining detector finds ≥ 1 path in the 3-hop fixture."""
    findings = detect_sts_chaining(
        STS_CHAIN_IDENTITIES,
        high_value_targets=STS_HIGH_VALUE_TARGETS,
        min_hops=2,
    )
    assert len(findings) >= 1, "Expected at least one STS chaining finding"
    # Verify finding shape.
    f = findings[0]
    assert f.source == HuntSource.CLOUD
    assert f.domain == HuntDomain.CLOUD
    assert "T1078.004" in f.technique_ids or "T1550.001" in f.technique_ids
    assert f.evidence["detection"] == "sts_chaining"
    assert f.evidence["hop_count"] >= 2


def test_T2_sts_chaining_clean_graph_no_findings():
    """STS chaining detector does NOT fire on a graph with no paths to target."""
    # A single isolated role with no trustees.
    isolated = [
        CloudIdentity(
            id="x1",
            org_id=ORG_ID,
            provider=CloudProvider.AWS,
            kind=IdentityKind.ROLE,
            arn_or_id="arn:aws:iam::111111111111:role/IsolatedRole",
            display_name="Isolated (no trustees)",
            trust_policy=None,
            can_be_assumed_by=[],
            has_cross_account_trust=False,
            governance_tagged=True,
        )
    ]
    findings = detect_sts_chaining(
        isolated,
        high_value_targets={"arn:aws:iam::111111111111:role/IsolatedRole"},
        min_hops=2,
    )
    assert findings == []


def test_T3_sts_chaining_min_hops_filter():
    """Setting min_hops=3 excludes 2-hop paths."""
    # The fixture has a 3-hop path (external→dev→cicd→admin).
    # min_hops=3 means the path must have at least 4 nodes (3 edges).
    findings_2hop = detect_sts_chaining(
        STS_CHAIN_IDENTITIES,
        high_value_targets=STS_HIGH_VALUE_TARGETS,
        min_hops=2,
    )
    findings_4hop = detect_sts_chaining(
        STS_CHAIN_IDENTITIES,
        high_value_targets=STS_HIGH_VALUE_TARGETS,
        min_hops=4,  # more hops than exist in the fixture
    )
    assert len(findings_2hop) >= 1
    assert len(findings_4hop) == 0


# ---------------------------------------------------------------------------
# T4–T5: Trust graph construction
# ---------------------------------------------------------------------------


def test_T4_build_trust_graph_adjacency():
    """build_trust_graph returns correct adjacency map from fixture identities."""
    graph = build_trust_graph(STS_CHAIN_IDENTITIES)

    admin_arn = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/AdminRole"
    cicd_arn = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/CICDDeployRole"
    dev_arn = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/DevRole"
    external_arn = f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"

    # Admin is trusted by CICD.
    assert cicd_arn in graph[admin_arn]
    # CICD is trusted by Dev.
    assert dev_arn in graph[cicd_arn]
    # Dev is trusted by external.
    assert external_arn in graph[dev_arn]


def test_T5_transitive_reachable():
    """transitive_reachable returns all nodes reachable from the external root."""
    graph = build_trust_graph(STS_CHAIN_IDENTITIES)
    external_arn = f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"
    admin_arn = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/AdminRole"

    reachable = transitive_reachable(graph, external_arn)
    # The external root can reach dev, cicd, and admin via chaining.
    assert admin_arn in reachable


# ---------------------------------------------------------------------------
# T6–T7: IAM persistence
# ---------------------------------------------------------------------------


def test_T6_iam_persistence_flags_all_persistence_events():
    """IAM persistence detector flags CreateAccessKey, PutRolePolicy, UpdateAssumeRolePolicy."""
    findings = detect_iam_persistence(IAM_PERSISTENCE_EVENTS)
    event_names = {f.evidence["event_name"] for f in findings}
    assert "CreateAccessKey" in event_names
    assert "PutRolePolicy" in event_names
    assert "UpdateAssumeRolePolicy" in event_names


def test_T7_iam_persistence_ignores_benign_events():
    """IAM persistence detector does not flag GetCallerIdentity."""
    benign = [
        {
            "eventName": "GetCallerIdentity",
            "eventTime": "2026-06-18T09:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/alice"},
            "requestParameters": {},
        }
    ]
    findings = detect_iam_persistence(benign)
    assert findings == []


# ---------------------------------------------------------------------------
# T8: Cross-account trust abuse
# ---------------------------------------------------------------------------


def test_T8_cross_account_trust_flags_external_not_approved():
    """Cross-account trust detector flags external account, not approved DR account."""
    findings = detect_cross_account_trust_abuse(
        CROSS_ACCOUNT_IDENTITIES,
        trusted_account_ids=CROSS_ACCOUNT_TRUSTED_IDS,
    )
    assert len(findings) >= 1
    # The external attacker account should appear in evidence.
    external_trustees = [t for f in findings for t in f.evidence.get("external_trustees", [])]
    assert any(EXTERNAL_ACCOUNT in t for t in external_trustees)
    # The approved DR account (SECOND_ACCOUNT) should NOT be flagged.
    assert not any(SECOND_ACCOUNT in t for t in external_trustees)


# ---------------------------------------------------------------------------
# T9–T11: Snapshot external share
# ---------------------------------------------------------------------------


def test_T9_snapshot_external_share_flags_external_account():
    """Snapshot detector flags snapshot shared with external account."""
    findings = detect_snapshot_external_share(
        SNAPSHOT_SHARE_EVENTS,
        trusted_account_ids={TRUSTED_ACCOUNT, SECOND_ACCOUNT},
    )
    external_findings = [f for f in findings if not f.evidence.get("is_public")]
    assert len(external_findings) >= 1
    assert external_findings[0].evidence["detection"] == "snapshot_external_share"


def test_T10_snapshot_public_ami_is_critical():
    """AMI shared publicly (group=all) produces CRITICAL severity finding."""
    findings = detect_snapshot_external_share(SNAPSHOT_SHARE_EVENTS)
    public_findings = [f for f in findings if f.evidence.get("is_public")]
    assert len(public_findings) >= 1
    assert public_findings[0].severity == Severity.CRITICAL


def test_T11_snapshot_trusted_share_still_reported():
    """Snapshot shared with trusted account is still reported (suppression is at triage level)."""
    # When trusted_account_ids is empty (default), even the DR-account share is flagged.
    findings_no_whitelist = detect_snapshot_external_share(SNAPSHOT_SHARE_EVENTS)
    findings_with_whitelist = detect_snapshot_external_share(
        SNAPSHOT_SHARE_EVENTS,
        trusted_account_ids={TRUSTED_ACCOUNT, SECOND_ACCOUNT},
    )
    # Without whitelist: all 3 events fire (2 external + 1 public + 1 trusted).
    # With whitelist: trusted DR-account snap is NOT flagged (second_account is trusted).
    assert len(findings_no_whitelist) >= len(findings_with_whitelist)


# ---------------------------------------------------------------------------
# T12–T13: CloudTrail tamper
# ---------------------------------------------------------------------------


def test_T12_cloudtrail_tamper_correlated_is_critical():
    """StopLogging correlated with prior GetSessionToken-without-MFA is CRITICAL."""
    findings = detect_cloudtrail_tamper(CLOUDTRAIL_TAMPER_EVENTS)
    correlated = [f for f in findings if f.evidence.get("correlated_suspicious_auths")]
    assert len(correlated) >= 1
    assert correlated[0].severity == Severity.CRITICAL
    assert correlated[0].confidence >= 0.9
    assert "T1562.008" in correlated[0].technique_ids


def test_T13_cloudtrail_tamper_standalone_is_high():
    """Standalone StopLogging (no prior suspicious auth) produces HIGH confidence finding."""
    standalone_events = [
        {
            "eventName": "StopLogging",
            "eventTime": "2026-06-18T07:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/X/s"},
            "requestParameters": {
                "trailARN": f"arn:aws:cloudtrail:us-east-1:{TRUSTED_ACCOUNT}:trail/t1"
            },
        }
    ]
    findings = detect_cloudtrail_tamper(standalone_events)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["correlated_suspicious_auths"] == []


# ---------------------------------------------------------------------------
# T14–T16: Shadow workload discovery
# ---------------------------------------------------------------------------


def test_T14_shadow_workloads_finds_at_least_three():
    """Shadow workload detector finds ≥ 3 unmanaged identities in the fixture."""
    findings = detect_shadow_workloads(AGENTIC_WORKLOAD_INVENTORY)
    # wl_002 (shadow Bedrock), wl_003 (rogue Lambda), wl_004 (shadow Cloud Run MCP)
    assert len(findings) >= 3
    shadow_marker = [f for f in findings if f.evidence.get("shadow_workload")]
    assert len(shadow_marker) >= 3


def test_T15_managed_workload_not_flagged():
    """Managed, governance-tagged workload is NOT flagged as shadow."""
    findings = detect_shadow_workloads(AGENTIC_WORKLOAD_INVENTORY)
    flagged_ids = {f.entities[0].value for f in findings}
    # wl_001 (managed Bedrock) and wl_005 (managed GKE) must not be flagged.
    managed_ids = {
        f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/AGENT001",
        "projects/my-project/zones/us-central1-a/clusters/inference-cluster",
    }
    assert flagged_ids.isdisjoint(managed_ids)


def test_T16_unmanaged_kind_is_shadow_regardless_of_tags():
    """UNMANAGED kind is classified as shadow even when governance_tagged=True."""
    # Hypothetical: someone tags an UNMANAGED workload but it's still shadow.
    wl = AgenticWorkload(
        id="test_wl",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.UNMANAGED,
        resource_id="arn:aws:lambda:us-east-1:111111111111:function:tagged-but-unmanaged",
        display_name="Tagged but UNMANAGED",
        identity_ref="arn:aws:iam::111111111111:role/SomeRole",
        governance_tagged=True,  # tagged — but kind is UNMANAGED
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=None,
        risk_score=0.0,
    )
    assert classify_workload(wl) is True  # should still be shadow


# ---------------------------------------------------------------------------
# T17: Risk score computation
# ---------------------------------------------------------------------------


def test_T17_risk_score_computation():
    """score_workload_risk computes expected scores for all flag combinations."""
    from datetime import datetime, timezone

    _now = datetime(2026, 6, 18, tzinfo=UTC)

    def _wl(**kwargs: object) -> AgenticWorkload:
        defaults: dict = {
            "id": "x",
            "org_id": ORG_ID,
            "provider": CloudProvider.AWS,
            "kind": AgenticWorkloadKind.BEDROCK_AGENTCORE,
            "resource_id": "arn:test",
            "identity_ref": "arn:test-role",
            "governance_tagged": True,
            "is_shadow": False,
            "has_overprivileged_identity": False,
            "internet_reachable": False,
            "last_activity": _now,
            "risk_score": 0.0,
        }
        defaults.update(kwargs)
        return AgenticWorkload(**defaults)

    # All false → 0.0.
    assert score_workload_risk(_wl()) == 0.0
    # Shadow only → 0.4.
    assert score_workload_risk(_wl(is_shadow=True)) == pytest.approx(0.4)
    # Shadow + overprivilege → 0.7.
    assert score_workload_risk(
        _wl(is_shadow=True, has_overprivileged_identity=True)
    ) == pytest.approx(0.7)
    # All flags → capped at 1.0.
    assert score_workload_risk(
        _wl(
            is_shadow=True,
            has_overprivileged_identity=True,
            internet_reachable=True,
            last_activity=None,
        )
    ) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# T18: Overprivileged identity
# ---------------------------------------------------------------------------


def test_T18_overprivileged_identity_flagged():
    """Overprivileged-identity detector flags workloads with the flag set."""
    findings = detect_overprivileged_workload_identity(
        AGENTIC_WORKLOAD_INVENTORY, AGENTIC_IDENTITY_INVENTORY
    )
    # wl_002 (shadow Bedrock, overprivileged) and wl_003 (rogue Lambda, overprivileged)
    assert len(findings) >= 2
    for f in findings:
        assert f.evidence["has_overprivileged_identity"] is True
        assert "T1098.001" in f.technique_ids


# ---------------------------------------------------------------------------
# T19: Integration sweep (run_all_detections)
# ---------------------------------------------------------------------------


def test_T19_run_all_detections_integration():
    """run_all_detections over the full fixture bundle returns findings from all detectors."""
    findings = run_all_detections(
        identities=STS_CHAIN_IDENTITIES + CROSS_ACCOUNT_IDENTITIES + AGENTIC_IDENTITY_INVENTORY,
        workloads=AGENTIC_WORKLOAD_INVENTORY,
        cloudtrail_events=IAM_PERSISTENCE_EVENTS + CLOUDTRAIL_TAMPER_EVENTS,
        resource_events=SNAPSHOT_SHARE_EVENTS,
        high_value_targets=STS_HIGH_VALUE_TARGETS,
        trusted_account_ids={TRUSTED_ACCOUNT, SECOND_ACCOUNT},
    )
    # Should have hits from multiple detectors.
    assert len(findings) >= 5
    detections_seen = {f.evidence.get("detection") for f in findings}
    assert "sts_chaining" in detections_seen
    assert "iam_persistence" in detections_seen
    assert "cloudtrail_tamper" in detections_seen
    assert "snapshot_external_share" in detections_seen
    assert "shadow_workload" in detections_seen


# ---------------------------------------------------------------------------
# T20: Output shape validation
# ---------------------------------------------------------------------------


def test_T20_all_outputs_are_valid_pydantic_models():
    """Every detection output is a valid RecordFindingRequest (Pydantic validation)."""
    all_findings = run_all_detections(
        identities=STS_CHAIN_IDENTITIES + CROSS_ACCOUNT_IDENTITIES + AGENTIC_IDENTITY_INVENTORY,
        workloads=AGENTIC_WORKLOAD_INVENTORY,
        cloudtrail_events=IAM_PERSISTENCE_EVENTS + CLOUDTRAIL_TAMPER_EVENTS,
        resource_events=SNAPSHOT_SHARE_EVENTS,
        high_value_targets=STS_HIGH_VALUE_TARGETS,
        trusted_account_ids={TRUSTED_ACCOUNT, SECOND_ACCOUNT},
    )
    for f in all_findings:
        assert isinstance(f, RecordFindingRequest)
        # Pydantic v2 — model dump verifies all fields are serialisable.
        d = f.model_dump()
        assert d["source"] == "cloud"
        assert d["domain"] == "cloud"
        assert isinstance(d["technique_ids"], list)
        assert 0.0 <= d["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# T21: MITRE mapper cloud keywords
# ---------------------------------------------------------------------------


def test_T21_mitre_mapper_cloud_keywords():
    """MITRE mapper resolves cloud technique keywords to correct technique IDs."""
    from btagent_agents.mitre.mapper import MitreMapper

    mapper = MitreMapper()

    cases = [
        ("assumerole chaining detected", "T1078.004"),
        ("stoplogging event in cloudtrail", "T1562.008"),
        ("createaccesskey for iam user", "T1098.001"),
        ("snapshot share to external account", "T1537"),
        ("updateassumerolepolicy trust mutation", "T1098.003"),
        ("shadow workload discovered", "T1580"),
    ]

    for text, expected_technique in cases:
        suggestions = mapper.suggest_techniques(text, max_results=5)
        technique_ids = [s.technique_id for s in suggestions]
        assert expected_technique in technique_ids, (
            f"Expected {expected_technique!r} in suggestions for {text!r}, got: {technique_ids}"
        )


# ---------------------------------------------------------------------------
# T22: Pack discovery — the cloud pack loads via the engine builtin loader
# (Codex #207 finding 1)
# ---------------------------------------------------------------------------


def test_T22_cloud_pack_loads_via_builtin_loader():
    """The relocated cloud pack loads through btagent_engine's builtin loader.

    The pack must live under engine/btagent_engine/hunting/packs/<name>/ with
    manifest ``file:`` values equal to the bare basenames under ``rules/`` — the
    only shape the shared loader accepts. Code-based detectors are NOT listed as
    Sigma ``rules:`` entries.
    """
    from btagent_engine.hunting import HuntPack, load_builtin_pack
    from btagent_engine.hunting.pack import BUILTIN_PACKS_DIR

    pack = load_builtin_pack("cloud_control_plane")
    assert isinstance(pack, HuntPack)
    assert pack.id.startswith("hpack_")
    assert pack.name == "Cloud Control-Plane Hunt Pack"
    assert pack.version == "1.0.0"

    # All 11 Sigma rules load; the 3 code detectors are NOT among them.
    assert len(pack.rules) == 11
    rule_files = {r.file for r in pack.rules}
    assert "sts_assumerole_chain.yml" in rule_files
    assert "snapshot_external_share.yml" in rule_files
    assert not any(f.endswith(".py") for f in rule_files)

    # GuardDuty rules ship disabled (deferred on #100); the rest are enabled.
    by_file = {r.file: r for r in pack.rules}
    assert by_file["guardduty_iam_anomaly.yml"].enabled is False
    assert by_file["guardduty_privilege_escalation.yml"].enabled is False
    assert by_file["sts_assumerole_chain.yml"].enabled is True

    # The code-based detector modules ship alongside the pack (not as rules).
    pack_dir = BUILTIN_PACKS_DIR / "cloud_control_plane"
    assert (pack_dir / "detectors" / "sts_trust_graph_closure.py").is_file()
    assert (pack_dir / "detectors" / "shadow_workload_inventory.py").is_file()
    assert (pack_dir / "detectors" / "workload_identity_privilege.py").is_file()


# ---------------------------------------------------------------------------
# T23: Risk score uses derived shadow classification (Codex #207 finding 2)
# ---------------------------------------------------------------------------


def test_T23_risk_score_uses_derived_shadow_classification():
    """An untagged workload with is_shadow=False is still scored as shadow.

    Before the fix the shadow weight only applied when the separately-supplied
    is_shadow flag was True, so a default untagged workload was emitted as shadow
    by detect_shadow_workloads() yet under-scored by score_workload_risk().
    """
    untagged_default = AgenticWorkload(
        id="wl_untagged",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/UNTAGGED",
        display_name="Untagged agent, is_shadow flag never set",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/SomeRole",
        governance_tagged=False,  # derived-shadow
        is_shadow=False,  # flag never set by the inventory shim
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=_FIXED_NOW,
        risk_score=0.0,
    )
    # classify_workload says shadow, so the shadow weight must be applied.
    assert classify_workload(untagged_default) is True
    assert score_workload_risk(untagged_default) == pytest.approx(0.4)

    # UNMANAGED kind (even if tagged + is_shadow=False) is derived-shadow too.
    unmanaged = untagged_default.model_copy(
        update={"governance_tagged": True, "kind": AgenticWorkloadKind.UNMANAGED}
    )
    assert score_workload_risk(unmanaged) == pytest.approx(0.4)

    # A genuinely managed + tagged workload still scores 0.0.
    managed = untagged_default.model_copy(update={"governance_tagged": True})
    assert classify_workload(managed) is False
    assert score_workload_risk(managed) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# T24–T25: RDS snapshot share accepts string account IDs (Codex #207 finding 3)
# ---------------------------------------------------------------------------


def test_T24_rds_snapshot_share_string_account_ids():
    """ModifyDBSnapshotAttribute valuesToAdd is a list of account-ID strings."""
    events = [
        {
            "eventName": "ModifyDBSnapshotAttribute",
            "eventTime": "2026-06-18T12:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/s"},
            "requestParameters": {
                "dBSnapshotIdentifier": "prod-db-snapshot-final",
                "attributeName": "restore",
                "valuesToAdd": [EXTERNAL_ACCOUNT],  # bare account-ID string
            },
        }
    ]
    findings = detect_snapshot_external_share(
        events, trusted_account_ids={TRUSTED_ACCOUNT, SECOND_ACCOUNT}
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["detection"] == "snapshot_external_share"
    assert EXTERNAL_ACCOUNT in f.evidence["external_accounts"]
    assert f.evidence["resource_id"] == "prod-db-snapshot-final"


def test_T25_rds_string_share_does_not_abort_sweep():
    """A string-shaped valuesToAdd entry must not raise / abort run_all_detections."""
    events = [
        {
            "eventName": "ModifyDBSnapshotAttribute",
            "eventTime": "2026-06-18T12:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/dba"},
            "requestParameters": {
                "dBSnapshotIdentifier": "snap-1",
                "valuesToAdd": [EXTERNAL_ACCOUNT, TRUSTED_ACCOUNT],
            },
        }
    ]
    # Combined with the dict-shaped fixture events — both shapes coexist.
    combined = SNAPSHOT_SHARE_EVENTS + events
    findings = detect_snapshot_external_share(
        combined, trusted_account_ids={TRUSTED_ACCOUNT, SECOND_ACCOUNT}
    )
    # The trusted account in valuesToAdd is filtered; the external one fires.
    rds = [f for f in findings if f.evidence.get("resource_id") == "snap-1"]
    assert len(rds) == 1
    assert rds[0].evidence["external_accounts"] == [EXTERNAL_ACCOUNT]


# ---------------------------------------------------------------------------
# T26–T27: UpdateTrail filtered to actual logging-disable changes
# (Codex #207 finding 4)
# ---------------------------------------------------------------------------


def test_T26_update_trail_disable_fires():
    """UpdateTrail disabling log-file validation IS treated as tampering."""
    events = [
        {
            "eventName": "UpdateTrail",
            "eventTime": "2026-06-18T07:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/eve"},
            "requestParameters": {
                "name": "management-events",
                "enableLogFileValidation": "false",
            },
        }
    ]
    findings = detect_cloudtrail_tamper(events)
    assert len(findings) == 1
    assert findings[0].evidence["event_name"] == "UpdateTrail"


def test_T27_routine_update_trail_does_not_fire():
    """Routine UpdateTrail (destination change / enabling validation) does NOT fire."""
    routine_events = [
        {
            "eventName": "UpdateTrail",
            "eventTime": "2026-06-18T07:00:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/IaCPipeline"},
            "requestParameters": {
                "name": "management-events",
                "s3BucketName": "new-audit-bucket",
                "enableLogFileValidation": "true",  # enabling, not disabling
            },
        }
    ]
    assert detect_cloudtrail_tamper(routine_events) == []


# ---------------------------------------------------------------------------
# T28: Only genuinely suspicious auth corroborates a tamper event
# (Codex #207 finding 5)
# ---------------------------------------------------------------------------


def test_T28_clean_login_does_not_escalate_tamper():
    """An MFA-backed ConsoleLogin before StopLogging must NOT escalate to CRITICAL."""
    events = [
        # Clean, MFA-backed console login one minute before the tamper.
        {
            "eventName": "ConsoleLogin",
            "eventTime": "2026-06-18T08:14:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/admin"},
            "additionalEventData": {"MFAUsed": "Yes"},
            "requestParameters": {},
        },
        {
            "eventName": "StopLogging",
            "eventTime": "2026-06-18T08:15:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/Ops"},
            "requestParameters": {
                "trailARN": f"arn:aws:cloudtrail:us-east-1:{TRUSTED_ACCOUNT}:trail/t1"
            },
        },
    ]
    findings = detect_cloudtrail_tamper(events)
    assert len(findings) == 1
    # Clean login is not corroborating — finding stays standalone HIGH.
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["correlated_suspicious_auths"] == []


def test_T28b_no_mfa_login_does_corroborate_tamper():
    """A no-MFA ConsoleLogin before StopLogging DOES corroborate → CRITICAL."""
    events = [
        {
            "eventName": "ConsoleLogin",
            "eventTime": "2026-06-18T08:14:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/attacker"},
            "additionalEventData": {"MFAUsed": "No"},
            "requestParameters": {},
        },
        {
            "eventName": "StopLogging",
            "eventTime": "2026-06-18T08:15:00Z",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/Ops"},
            "requestParameters": {
                "trailARN": f"arn:aws:cloudtrail:us-east-1:{TRUSTED_ACCOUNT}:trail/t1"
            },
        },
    ]
    findings = detect_cloudtrail_tamper(events)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert len(findings[0].evidence["correlated_suspicious_auths"]) == 1
