"""Test persistence of Hunt Pack Runner findings into the #119 store (#112).

The runner itself (compile + execute) is tested in agents/tests; this verifies
the backend side: runner-emitted RecordFindingRequest payloads land as
clustered HuntFinding rows via the shared store service.
"""

from btagent_shared.types.hunt_finding import RecordFindingRequest

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_triage_service as svc


def _req(host: str) -> RecordFindingRequest:
    return RecordFindingRequest(
        source="hunt_pack",
        domain="sigma",
        title="Encoded PowerShell",
        severity="high",
        technique_ids=["T1059.001"],
        entities=[{"kind": "host", "value": host}],
        evidence={"pack_id": "sigmahq-windows", "rule_id": "rule_1", "run_id": "hrun_1"},
    )


async def test_persist_hunt_findings_lands_clustered_rows(db_session):
    findings = [_req("WS-1"), _req("WS-2")]
    rows = await svc.persist_hunt_findings(db_session, org_id=DEFAULT_ORG_ID, findings=findings)

    assert len(rows) == 2
    # Both share the same signature (same domain/technique/entity-kind) -> one cluster.
    cluster_ids = {r.cluster_id for r in rows}
    assert len(cluster_ids) == 1
    assert all(r.state == "clustered" for r in rows)
    assert all(r.evidence["pack_id"] == "sigmahq-windows" for r in rows)


async def test_persist_empty_is_noop(db_session):
    rows = await svc.persist_hunt_findings(db_session, org_id=DEFAULT_ORG_ID, findings=[])
    assert rows == []


async def test_rule_ids_suppression_suppresses_matching_rule_only(db_session, sample_user):
    """#112 noise-baseline loop: a rule_ids suppression mutes exactly the
    chronically noisy rule — sibling rules in the same pack/domain still land
    clustered."""
    from btagent_shared.types.hunt_finding import SuppressionMatch
    from btagent_shared.utils.ids import generate_id

    noisy_rule = generate_id("rule")
    quiet_rule = generate_id("rule")
    await svc.create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name=f"mute {noisy_rule}",
        reason="chronically noisy per the noise baseline",
        match=SuppressionMatch(rule_ids=[noisy_rule]),
        created_by=sample_user.id,
    )

    def req(rule_id: str, host: str) -> RecordFindingRequest:
        return RecordFindingRequest(
            source="hunt_pack",
            domain="sigma",
            title=f"Rule {rule_id}",
            severity="medium",
            technique_ids=["T1059.001"],
            entities=[{"kind": "host", "value": host}],
            evidence={"pack_id": "sigmahq-windows", "rule_id": rule_id},
        )

    rows = await svc.persist_hunt_findings(
        db_session,
        org_id=DEFAULT_ORG_ID,
        findings=[req(noisy_rule, "WS-9"), req(quiet_rule, "WS-9")],
    )
    by_rule = {r.evidence["rule_id"]: r for r in rows}
    assert by_rule[noisy_rule].state == "suppressed"
    assert by_rule[quiet_rule].state != "suppressed"
