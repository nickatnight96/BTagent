"""Pure-logic tests for the revoke-playbook proposal builder (#116 Phase C).

``build_revocation_proposal`` turns promoted identity findings into an inert
:class:`RevocationProposal` — target extraction/dedup and playbook-spec shape
are all deterministic pure logic, so they're tested here with no DB or HTTP.
The backend accept-endpoint test proves the generated spec passes the real
playbook validator.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from btagent_shared.hunt.identity import build_revocation_proposal
from btagent_shared.types.hunt_finding import HuntDomain, HuntFinding, HuntSource
from btagent_shared.types.identity_hunt import IdentityProvider, RevocationProposalStatus

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def _finding(
    finding_id: str,
    *,
    principal_id: str | None = "alice@example.com",
    app_id: str | None = "app_slack",
    provider: str = "okta",
    scopes: list[str] | None = None,
    app_display_name: str = "Slack",
    domain: HuntDomain = HuntDomain.IDENTITY,
    title: str = "Dormant OAuth app reactivated",
) -> HuntFinding:
    evidence: dict[str, Any] = {
        "provider": provider,
        "app_display_name": app_display_name,
        "scopes": scopes if scopes is not None else ["openid", "profile"],
    }
    if principal_id is not None:
        evidence["principal_id"] = principal_id
    if app_id is not None:
        evidence["app_id"] = app_id
    return HuntFinding(
        id=finding_id,
        org_id="org_default",
        source=HuntSource.IDENTITY,
        domain=domain,
        title=title,
        evidence=evidence,
        created_at=_NOW,
        updated_at=_NOW,
    )


# --------------------------------------------------------------------------- #
# No-proposal cases
# --------------------------------------------------------------------------- #


def test_empty_findings_yield_no_proposal() -> None:
    assert build_revocation_proposal([]) is None


def test_non_identity_findings_yield_no_proposal() -> None:
    finding = _finding("hfnd_1", domain=HuntDomain.BEHAVIORAL)
    assert build_revocation_proposal([finding]) is None


def test_identity_findings_without_grant_tuple_yield_no_proposal() -> None:
    # Token-replay / impossible-travel findings carry no app_id — nothing to revoke.
    replay = _finding("hfnd_1", app_id=None, title="Token replay across ASNs")
    assert build_revocation_proposal([replay]) is None


# --------------------------------------------------------------------------- #
# Target extraction + dedup
# --------------------------------------------------------------------------- #


def test_targets_dedup_by_provider_principal_app() -> None:
    a = _finding("hfnd_1", scopes=["openid"])
    b = _finding("hfnd_2", scopes=["profile", "Mail.Read"])
    proposal = build_revocation_proposal([a, b])
    assert proposal is not None
    assert len(proposal.targets) == 1
    target = proposal.targets[0]
    # Scope sets merge; source finding IDs accumulate.
    assert target.scopes == sorted({"openid", "profile", "Mail.Read"})
    assert target.source_finding_ids == ["hfnd_1", "hfnd_2"]
    assert target.provider is IdentityProvider.OKTA


def test_distinct_providers_are_distinct_targets() -> None:
    okta = _finding("hfnd_1", provider="okta")
    entra = _finding("hfnd_2", provider="entra")
    proposal = build_revocation_proposal([okta, entra])
    assert proposal is not None
    assert len(proposal.targets) == 2
    assert {t.provider for t in proposal.targets} == {
        IdentityProvider.OKTA,
        IdentityProvider.ENTRA,
    }


def test_non_grant_findings_are_skipped_not_fatal() -> None:
    grant = _finding("hfnd_1")
    replay = _finding("hfnd_2", app_id=None, title="Token replay across ASNs")
    proposal = build_revocation_proposal([grant, replay])
    assert proposal is not None
    assert len(proposal.targets) == 1
    assert proposal.targets[0].source_finding_ids == ["hfnd_1"]


def test_target_ordering_is_deterministic() -> None:
    findings = [
        _finding("hfnd_1", principal_id="bob@example.com", app_id="app_zoom"),
        _finding("hfnd_2", principal_id="alice@example.com", app_id="app_slack"),
    ]
    p1 = build_revocation_proposal(findings)
    p2 = build_revocation_proposal(list(reversed(findings)))
    assert p1 is not None and p2 is not None
    assert [(t.principal_id, t.app_id) for t in p1.targets] == [
        (t.principal_id, t.app_id) for t in p2.targets
    ]


# --------------------------------------------------------------------------- #
# Playbook spec shape
# --------------------------------------------------------------------------- #


def test_playbook_spec_is_hitl_gated_and_linear() -> None:
    findings = [
        _finding("hfnd_1", principal_id="alice@example.com", app_id="app_slack"),
        _finding("hfnd_2", principal_id="bob@example.com", app_id="app_zoom"),
    ]
    proposal = build_revocation_proposal(findings)
    assert proposal is not None
    assert proposal.status is RevocationProposalStatus.PROPOSED
    assert proposal.playbook_id is None

    spec = proposal.playbook_spec
    steps = spec["steps"]
    assert spec["trigger"] == {"type": "manual", "parameters": {}}

    # HITL gate first — nothing destructive runs without a human approval.
    assert steps[0]["type"] == "hitl_gate"
    assert steps[0]["required_role"] == "senior_analyst"

    # One revoke-grant action per target, one revoke-sessions per principal.
    revoke_grants = [s for s in steps if s.get("tool_name") == "identity_revoke_grant"]
    revoke_sessions = [s for s in steps if s.get("tool_name") == "identity_revoke_sessions"]
    assert len(revoke_grants) == 2
    assert len(revoke_sessions) == 2
    assert steps[-1]["type"] == "end"

    # The chain is linear and closed: every next_step references a real step.
    step_ids = {s["id"] for s in steps}
    for step in steps:
        if "next_step" in step:
            assert step["next_step"] in step_ids


def test_rationale_names_the_source_findings() -> None:
    finding = _finding("hfnd_1", title="Dormant OAuth app reactivated: Slack")
    proposal = build_revocation_proposal([finding])
    assert proposal is not None
    assert "Dormant OAuth app reactivated: Slack" in proposal.rationale
    assert "1 OAuth grant(s)" in proposal.rationale
