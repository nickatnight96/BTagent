"""Phase A acceptance tests for the Hunt Triage Agent (#119).

API-driven (test_workflow_autonomy idiom) coverage of the issue's
acceptance criteria that aren't already exercised by
test_hunt_findings_api.py:

* deterministic clustering: 20 findings over 3 patterns -> exactly 3 clusters
* an active suppression rule filters the *next* ingest pre-insert
* an expired-but-unswept rule does NOT filter new findings
* suppression rationale is mandatory (422 at the API, ValueError in the service)
* cluster-level bulk suppress / promote endpoints (incl. derived match)
* suppress + promote land on the SHA-256 audit chain (category ``hunt``)
* RBAC: analyst is 403 on cluster suppress/promote
* org scoping: cross-tenant finding/cluster actions 404 (IDOR-safe)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from btagent_shared.types.hunt_finding import SuppressionMatch
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow, OrganizationRow, UserRow
from btagent_backend.db.models_hunt import SuppressionRuleRow
from btagent_backend.services import hunt_triage_service as svc

# --------------------------------------------------------------------------- #
# Fixtures + helpers
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture(autouse=True)
async def _isolate_audit_log(db_session: AsyncSession):
    """Clear audit_logs before + after each test (shared in-memory DB)."""
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(AuditLogRow))
    await db_session.commit()


@pytest_asyncio.fixture()
async def org_b_admin_token(db_session: AsyncSession) -> str:
    """An admin in a *different* organization (cross-tenant probe)."""
    org_id = "org_b_hunt"
    if await db_session.get(OrganizationRow, org_id) is None:
        db_session.add(OrganizationRow(id=org_id, name="org-b-hunt"))
        await db_session.flush()
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"orgb_admin_{generate_id('n')}",
        email=f"orgb_admin_{generate_id('e')}@btagent.test",
        password_hash=hash_password("OrgB!2026pass"),
        role="admin",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return create_token_pair(user.id, user.username, user.role, org_id=org_id).access_token


def _finding_body(technique: str, host: str, **overrides) -> dict:
    body = {
        "source": "hunt_pack",
        "domain": "sigma",
        "title": f"Pattern {technique}",
        "description": "synthetic phase-a finding",
        "severity": "medium",
        "confidence": 0.6,
        "technique_ids": [technique],
        "entities": [{"kind": "host", "value": host}],
        "observables": [{"type": "process_name", "value": "synthetic.exe"}],
        "evidence": {"rule": f"rule_{technique}"},
    }
    body.update(overrides)
    return body


async def _post_finding(client: AsyncClient, token: str, body: dict) -> dict:
    resp = await client.post("/api/v1/hunt/findings", json=body, headers=auth_header(token))
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _post_decoys(client: AsyncClient, token: str, n: int = 4) -> None:
    """Seed unrelated findings so single-pattern suppressions stay under the
    over-broad match-fraction gate regardless of which tests ran before."""
    for _ in range(n):
        await _post_finding(
            client, token, _finding_body(f"T9{generate_id('x')[-4:].upper()}", "DECOY")
        )


async def _hunt_audit_rows(db_session: AsyncSession) -> list[AuditLogRow]:
    rows = await db_session.execute(
        select(AuditLogRow).where(AuditLogRow.category == "hunt").order_by(AuditLogRow.seq)
    )
    return list(rows.scalars().all())


# --------------------------------------------------------------------------- #
# Clustering acceptance
# --------------------------------------------------------------------------- #


async def test_twenty_findings_three_patterns_yield_three_clusters(client, analyst_token):
    """Issue #119 acceptance (scaled down deterministically): repeated
    patterns collapse — 20 findings over 3 patterns -> exactly 3 clusters."""
    patterns = [
        ("T1059.901", 8),
        ("T1021.901", 7),
        ("T1566.901", 5),
    ]
    cluster_ids: set[str] = set()
    total = 0
    for technique, count in patterns:
        for i in range(count):
            data = await _post_finding(
                client, analyst_token, _finding_body(technique, f"WS-{technique}-{i:02d}")
            )
            assert data["state"] == "clustered"
            assert data["cluster_id"] is not None
            cluster_ids.add(data["cluster_id"])
            total += 1

    assert total == 20
    assert len(cluster_ids) == 3


# --------------------------------------------------------------------------- #
# Suppression lifecycle
# --------------------------------------------------------------------------- #


async def test_active_suppression_filters_next_ingest(client, analyst_token, admin_token):
    await _post_decoys(client, analyst_token)
    first = await _post_finding(client, analyst_token, _finding_body("T1110.902", "WS-SUP-A"))
    assert first["state"] == "clustered"

    supp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "known brute-force scanner noise",
            "reason": "authorized red-team scanner, ticket SEC-1234",
            "match": {"technique_ids": ["T1110.902"]},
        },
        headers=auth_header(admin_token),
    )
    assert supp.status_code == 201, supp.text

    # The NEXT matching ingest is suppressed pre-insert.
    second = await _post_finding(client, analyst_token, _finding_body("T1110.902", "WS-SUP-B"))
    assert second["state"] == "suppressed"
    assert second["suppressed_by"] == supp.json()["id"]

    # ...and a non-matching ingest is untouched.
    other = await _post_finding(client, analyst_token, _finding_body("T1110.903", "WS-SUP-C"))
    assert other["state"] == "clustered"


async def test_expired_suppression_does_not_filter_ingest(
    client, analyst_token, db_session: AsyncSession
):
    """An ACTIVE rule past its expires_at must not hide new findings, even
    before the stale-suppression sweep has flipped its state."""
    now = datetime.now(UTC)
    rule = SuppressionRuleRow(
        id=generate_id("supp"),
        org_id=DEFAULT_ORG_ID,
        name="lapsed rule",
        reason="expired maintenance window",
        match={"technique_ids": ["T1490.902"]},
        state="active",
        match_count=0,
        created_at=now - timedelta(days=31),
        expires_at=now - timedelta(days=1),
    )
    db_session.add(rule)
    await db_session.commit()

    data = await _post_finding(client, analyst_token, _finding_body("T1490.902", "WS-EXP-A"))
    assert data["state"] == "clustered"
    assert data["suppressed_by"] is None


async def test_suppression_rationale_required_api(client, analyst_token, admin_token):
    first = await _post_finding(client, analyst_token, _finding_body("T1547.902", "WS-RAT-A"))
    resp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "no rationale",
            "reason": "",
            "match": {"technique_ids": ["T1547.902"]},
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 422, resp.text


async def test_suppression_blank_rationale_service_value_error(db_session: AsyncSession):
    """Defense in depth below Pydantic: whitespace-only rationale raises."""
    with pytest.raises(ValueError, match="rationale"):
        await svc.create_suppression(
            db_session,
            org_id=DEFAULT_ORG_ID,
            name="blank",
            reason="   ",
            match=SuppressionMatch(technique_ids=["T0000.000"]),
            created_by=None,
        )


# --------------------------------------------------------------------------- #
# Cluster-level actions
# --------------------------------------------------------------------------- #


async def test_cluster_suppress_derived_match_suppresses_members_and_audits(
    client, analyst_token, admin_token, db_session: AsyncSession
):
    await _post_decoys(client, analyst_token)
    a = await _post_finding(client, analyst_token, _finding_body("T1095.902", "WS-CSU-A"))
    b = await _post_finding(client, analyst_token, _finding_body("T1095.902", "WS-CSU-B"))
    assert a["cluster_id"] == b["cluster_id"]
    cluster_id = a["cluster_id"]

    resp = await client.post(
        f"/api/v1/hunt/clusters/{cluster_id}/suppress",
        json={"name": "noisy pack rule", "reason": "tuned out per SOC review 2026-06"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    rule = resp.json()
    assert rule["state"] == "active"
    assert rule["match_count"] >= 2
    # Derived match carries the cluster's pattern (domain + techniques).
    assert rule["match"]["domain"] == "sigma"
    assert rule["match"]["technique_ids"] == ["T1095.902"]

    for fid in (a["id"], b["id"]):
        detail = await client.get(
            f"/api/v1/hunt/findings/{fid}", headers=auth_header(analyst_token)
        )
        assert detail.json()["state"] == "suppressed"

    # A future finding of the same pattern on a NEW host is suppressed too.
    c = await _post_finding(client, analyst_token, _finding_body("T1095.902", "WS-CSU-NEW"))
    assert c["state"] == "suppressed"

    rows = await _hunt_audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0].action == "suppress"
    assert rows[0].resource == f"suppression:{rule['id']}"
    assert rows[0].details["target"] == f"hunt_cluster:{cluster_id}"
    assert rows[0].details["reason"] == "tuned out per SOC review 2026-06"


async def test_cluster_promote_creates_one_investigation_and_audits(
    client, analyst_token, admin_token, db_session: AsyncSession
):
    a = await _post_finding(client, analyst_token, _finding_body("T1572.902", "WS-CPR-A"))
    b = await _post_finding(client, analyst_token, _finding_body("T1572.902", "WS-CPR-B"))
    cluster_id = a["cluster_id"]

    resp = await client.post(
        f"/api/v1/hunt/clusters/{cluster_id}/promote",
        json={"title": "Escalated tunneling pattern"},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    inv_id = resp.json()["investigation_id"]
    assert inv_id.startswith("inv_")
    assert set(resp.json()["promoted_finding_ids"]) == {a["id"], b["id"]}

    for fid in (a["id"], b["id"]):
        detail = await client.get(
            f"/api/v1/hunt/findings/{fid}", headers=auth_header(analyst_token)
        )
        assert detail.json()["state"] == "promoted"
        assert detail.json()["investigation_id"] == inv_id

    # The investigation is real and org-scoped (readable through the API).
    inv = await client.get(f"/api/v1/investigations/{inv_id}", headers=auth_header(admin_token))
    assert inv.status_code == 200, inv.text

    rows = await _hunt_audit_rows(db_session)
    assert len(rows) == 1
    assert rows[0].action == "promote"
    assert rows[0].resource == f"investigation:{inv_id}"
    assert set(rows[0].details["hunt_finding_ids"]) == {a["id"], b["id"]}

    # Re-promoting an already-promoted cluster is a 409 (no eligible members).
    again = await client.post(
        f"/api/v1/hunt/clusters/{cluster_id}/promote",
        json={},
        headers=auth_header(admin_token),
    )
    assert again.status_code == 409, again.text


async def test_finding_level_suppress_and_promote_are_audited(
    client, analyst_token, admin_token, db_session: AsyncSession
):
    await _post_decoys(client, analyst_token)
    f1 = await _post_finding(client, analyst_token, _finding_body("T1003.902", "WS-AUD-A"))
    supp = await client.post(
        f"/api/v1/hunt/findings/{f1['id']}/suppress",
        json={
            "name": "lab host",
            "reason": "credential-dumping lab exercise",
            "match": {"entity_values": ["WS-AUD-A"]},
        },
        headers=auth_header(admin_token),
    )
    assert supp.status_code == 201, supp.text

    f2 = await _post_finding(client, analyst_token, _finding_body("T1003.903", "WS-AUD-B"))
    promo = await client.post(
        "/api/v1/hunt/findings/promote",
        json={"finding_ids": [f2["id"]]},
        headers=auth_header(admin_token),
    )
    assert promo.status_code == 201, promo.text

    rows = await _hunt_audit_rows(db_session)
    assert [r.action for r in rows] == ["suppress", "promote"]
    assert rows[0].details["target"] == f"hunt_finding:{f1['id']}"
    assert all(r.actor for r in rows)


# --------------------------------------------------------------------------- #
# RBAC + org scoping
# --------------------------------------------------------------------------- #


async def test_cluster_actions_require_senior(client, analyst_token):
    a = await _post_finding(client, analyst_token, _finding_body("T1219.902", "WS-RBAC-A"))
    cluster_id = a["cluster_id"]

    supp = await client.post(
        f"/api/v1/hunt/clusters/{cluster_id}/suppress",
        json={"name": "nope", "reason": "analyst cannot suppress"},
        headers=auth_header(analyst_token),
    )
    assert supp.status_code == 403, supp.text

    promo = await client.post(
        f"/api/v1/hunt/clusters/{cluster_id}/promote",
        json={},
        headers=auth_header(analyst_token),
    )
    assert promo.status_code == 403, promo.text


async def test_cross_org_actions_404(client, analyst_token, org_b_admin_token):
    """Cross-tenant access to findings/clusters is always 404, never 200/403."""
    a = await _post_finding(client, analyst_token, _finding_body("T1071.902", "WS-XORG-A"))
    finding_id, cluster_id = a["id"], a["cluster_id"]
    hdrs = auth_header(org_b_admin_token)

    assert (
        await client.get(f"/api/v1/hunt/findings/{finding_id}", headers=hdrs)
    ).status_code == 404

    supp_body = {
        "name": "x",
        "reason": "cross-org probe",
        "match": {"technique_ids": ["T1071.902"]},
    }
    r = await client.post(
        f"/api/v1/hunt/findings/{finding_id}/suppress", json=supp_body, headers=hdrs
    )
    assert r.status_code == 404, r.text

    r = await client.post(
        "/api/v1/hunt/findings/promote", json={"finding_ids": [finding_id]}, headers=hdrs
    )
    assert r.status_code == 404, r.text

    r = await client.post(
        f"/api/v1/hunt/clusters/{cluster_id}/suppress",
        json={"name": "x", "reason": "cross-org probe"},
        headers=hdrs,
    )
    assert r.status_code == 404, r.text

    r = await client.post(f"/api/v1/hunt/clusters/{cluster_id}/promote", json={}, headers=hdrs)
    assert r.status_code == 404, r.text
