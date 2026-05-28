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
