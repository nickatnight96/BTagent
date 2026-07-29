"""Pure-logic tests for the cloud IAM containment proposal builder (#117 Phase C).

:func:`btagent_shared.hunt.cloud.build_cloud_containment_proposal` is the
IAM/STS → IR bridge: it turns promoted cloud control-plane findings into INERT
containment proposals (revoke role / freeze access key / detach policy). These
tests pin the *shape and restraint* of that mapping:

* the three verbs are derived from the right detections and name the right
  principal (a full ARN, rebuilt from the actor's account),
* non-IAM findings and non-containable IAM events produce nothing,
* dedup across findings, and
* the proposal is inert — every action lands ``proposed``, with no execution
  state, no credential, and no connector call anywhere in this module.

No DB, no network, no connectors: the builder is dependency-free by design.
"""

from __future__ import annotations

from datetime import UTC, datetime

from btagent_shared.hunt.cloud import (
    build_cloud_containment_proposal,
    detect_cross_account_trust_abuse,
    detect_iam_persistence,
    detect_shadow_workloads,
    detect_sts_chaining,
)
from btagent_shared.types.cloud_hunt import (
    CloudContainmentActionStatus,
    CloudContainmentActionType,
    CloudProvider,
)
from btagent_shared.types.hunt import HuntFindingState
from btagent_shared.types.hunt_finding import HuntFinding, RecordFindingRequest

from tests.fixtures.cloud.iam_fixtures import (
    AGENTIC_WORKLOAD_INVENTORY,
    BREAK_GLASS_ROLE_ARN,
    CONTAINMENT_DETACH_TARGET,
    CONTAINMENT_FREEZE_TARGET,
    CONTAINMENT_REVOKE_TARGET,
    CROSS_ACCOUNT_IDENTITIES,
    CROSS_ACCOUNT_TRUSTED_IDS,
    IAM_CONTAINMENT_EVENTS,
    ORG_ID,
    SAFELISTED_CONTAINMENT_EVENTS,
    STS_CHAIN_IDENTITIES,
    STS_HIGH_VALUE_TARGETS,
)

_NOW = datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)


def _as_findings(requests: list[RecordFindingRequest]) -> list[HuntFinding]:
    """Materialise detector output as stored findings (what promotion sees)."""
    return [
        HuntFinding(
            id=f"hfnd_{index:04d}",
            org_id=ORG_ID,
            source=req.source,
            domain=req.domain,
            title=req.title,
            description=req.description,
            severity=req.severity,
            confidence=req.confidence,
            technique_ids=list(req.technique_ids),
            entities=list(req.entities),
            observables=list(req.observables),
            state=HuntFindingState.NEW,
            evidence=dict(req.evidence),
            created_at=_NOW,
            updated_at=_NOW,
        )
        for index, req in enumerate(requests, start=1)
    ]


# --------------------------------------------------------------------------- #
# The three verbs, from the detections that imply them
# --------------------------------------------------------------------------- #


def test_iam_persistence_maps_to_the_three_containment_verbs():
    findings = _as_findings(detect_iam_persistence(IAM_CONTAINMENT_EVENTS))
    proposal = build_cloud_containment_proposal(findings)

    assert proposal is not None
    by_target = {a.target: a for a in proposal.actions}

    freeze = by_target[CONTAINMENT_FREEZE_TARGET]
    assert freeze.action_type is CloudContainmentActionType.FREEZE_ACCESS_KEY
    assert freeze.parameters["event_name"] == "CreateAccessKey"

    detach = by_target[CONTAINMENT_DETACH_TARGET]
    assert detach.action_type is CloudContainmentActionType.DETACH_POLICY
    assert detach.parameters["policy_name"] == "AdminAccess"

    revoke = by_target[CONTAINMENT_REVOKE_TARGET]
    assert revoke.action_type is CloudContainmentActionType.REVOKE_ROLE
    assert revoke.parameters["event_name"] == "UpdateAssumeRolePolicy"

    # Every action names an AWS connector and carries its source finding.
    for action in proposal.actions:
        assert action.provider is CloudProvider.AWS
        assert action.connector == "aws_iam"
        assert action.source_finding_ids


def test_non_containable_iam_events_propose_nothing():
    """DeactivateMFADevice is a real finding but none of the three verbs undo it.

    Proposing revoke/freeze/detach for it would be containment theatre: the
    analyst would approve an action that does not actually remove the attacker's
    capability. The builder stays silent instead.
    """
    findings = _as_findings(detect_iam_persistence(IAM_CONTAINMENT_EVENTS))
    mfa_findings = [f for f in findings if f.evidence.get("event_name") == "DeactivateMFADevice"]
    assert mfa_findings, "fixture should still produce the MFA persistence finding"
    assert build_cloud_containment_proposal(mfa_findings) is None


def test_sts_chaining_proposes_every_hop_except_the_high_value_target():
    """Containment breaks the pivot; it does not revoke the admin role itself.

    Revoking the destination (an admin / billing role) is the outage, not the
    fix — so the high-value target is deliberately never proposed.
    """
    findings = _as_findings(
        detect_sts_chaining(STS_CHAIN_IDENTITIES, high_value_targets=STS_HIGH_VALUE_TARGETS)
    )
    assert findings, "fixture should produce at least one chaining finding"
    proposal = build_cloud_containment_proposal(findings)
    assert proposal is not None

    targets = {a.target for a in proposal.actions}
    assert targets, "each chain hop should be proposed for revocation"
    assert targets.isdisjoint(STS_HIGH_VALUE_TARGETS)
    assert all(a.action_type is CloudContainmentActionType.REVOKE_ROLE for a in proposal.actions)


def test_cross_account_trust_abuse_proposes_role_revocation():
    findings = _as_findings(
        detect_cross_account_trust_abuse(
            CROSS_ACCOUNT_IDENTITIES, trusted_account_ids=CROSS_ACCOUNT_TRUSTED_IDS
        )
    )
    assert findings
    proposal = build_cloud_containment_proposal(findings)
    assert proposal is not None
    assert all(a.action_type is CloudContainmentActionType.REVOKE_ROLE for a in proposal.actions)
    for action in proposal.actions:
        assert action.parameters["reason"] == "cross_account_trust_abuse"
        assert action.parameters["external_trustees"]


# --------------------------------------------------------------------------- #
# Restraint: what must NOT produce a containment proposal
# --------------------------------------------------------------------------- #


def test_non_iam_cloud_findings_propose_nothing():
    """Shadow-workload governance findings are not IAM containment material."""
    findings = _as_findings(detect_shadow_workloads(AGENTIC_WORKLOAD_INVENTORY))
    assert findings
    assert build_cloud_containment_proposal(findings) is None


def test_empty_and_non_cloud_batches_propose_nothing():
    assert build_cloud_containment_proposal([]) is None


# --------------------------------------------------------------------------- #
# Dedup + inertness
# --------------------------------------------------------------------------- #


def test_duplicate_findings_collapse_to_one_action_carrying_both_sources():
    events = IAM_CONTAINMENT_EVENTS + IAM_CONTAINMENT_EVENTS
    findings = _as_findings(detect_iam_persistence(events))
    proposal = build_cloud_containment_proposal(findings)
    assert proposal is not None

    targets = [a.target for a in proposal.actions]
    assert len(targets) == len(set(targets)), "duplicate events must dedup by (verb, target)"
    for action in proposal.actions:
        assert len(action.source_finding_ids) == 2


def test_proposal_is_inert_and_ids_are_stable():
    findings = _as_findings(detect_iam_persistence(IAM_CONTAINMENT_EVENTS))
    first = build_cloud_containment_proposal(findings)
    second = build_cloud_containment_proposal(findings)
    assert first is not None and second is not None

    # Inert: nothing decided, nothing executed, no audit trail yet.
    assert first.status.value == "proposed"
    assert first.decided_by is None and first.decided_at is None
    for action in first.actions:
        assert action.status is CloudContainmentActionStatus.PROPOSED
        assert action.audit_id is None
        assert action.outcome == ""

    # Deterministic ordering + ids so a UI (and a partial accept) can address
    # a specific action across reloads.
    assert [a.id for a in first.actions] == [a.id for a in second.actions]
    assert [a.target for a in first.actions] == [a.target for a in second.actions]


def test_safelisted_fixture_still_produces_a_proposal():
    """The safelist refuses at EXECUTE time, not at proposal time.

    Suppressing the proposal would hide the finding's operational consequence
    from the analyst; the honest behaviour is to propose it and let the audited
    denial explain why it cannot run.
    """
    findings = _as_findings(detect_iam_persistence(SAFELISTED_CONTAINMENT_EVENTS))
    proposal = build_cloud_containment_proposal(findings)
    assert proposal is not None
    assert [a.target for a in proposal.actions] == [BREAK_GLASS_ROLE_ARN]
