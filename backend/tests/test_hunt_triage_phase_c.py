"""Phase C acceptance tests for the Hunt Triage Agent (#119 Phase C).

Covers:
* harmful_flag flip when a promoted finding matches an active suppression rule
* over-broad suppression rejected for analyst
* over-broad suppression allowed for IC with acknowledge_overbroad + audited
* harmful_suppressions() pure helper

These tests must coexist with the Phase A / logic test suites (no shared state
reliance — each test uses isolated techniques and the ``_post_decoys`` helper
to keep the over-broad gate stable).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.hunt import triage
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntFinding,
    HuntObservable,
    SuppressionMatch,
)
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import DEFAULT_ORG_ID, AuditLogRow, UserRow
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
async def ic_user(db_session: AsyncSession) -> UserRow:
    """An incident_commander user in the default org."""
    n = generate_id("n")
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"ic_user_{n}",
        email=f"ic_{n}@btagent.test",
        password_hash=hash_password("ICpass!2026"),
        role="incident_commander",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture()
async def ic_token(ic_user: UserRow) -> str:
    """Valid JWT access token for the incident_commander user."""
    return create_token_pair(
        ic_user.id, ic_user.username, ic_user.role, org_id=DEFAULT_ORG_ID
    ).access_token


def _finding_body(technique: str, host: str, **overrides) -> dict:
    body = {
        "source": "hunt_pack",
        "domain": "sigma",
        "title": f"Pattern {technique}",
        "description": "synthetic phase-c finding",
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


async def _post_decoys(client: AsyncClient, token: str, n: int = 6) -> None:
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


def _pure_finding(
    *,
    fid: str = "hfnd_x",
    domain: HuntDomain = HuntDomain.SIGMA,
    source: HuntSource = HuntSource.HUNT_PACK,
    technique_ids: list[str] | None = None,
    entities: list[HuntEntity] | None = None,
) -> HuntFinding:
    now = datetime.now(UTC)
    return HuntFinding(
        id=fid,
        org_id="org_default",
        source=source,
        domain=domain,
        title="t",
        severity=Severity.MEDIUM,
        technique_ids=technique_ids or [],
        entities=entities or [],
        observables=[],
        created_at=now,
        updated_at=now,
    )


# --------------------------------------------------------------------------- #
# Task 1: harmful_suppressions() pure helper
# --------------------------------------------------------------------------- #


def test_harmful_suppressions_detects_matching_rule():
    """A rule whose match covers a promoted finding is returned."""
    match_a = SuppressionMatch(technique_ids=["T9001"])
    match_b = SuppressionMatch(technique_ids=["T9999"])  # won't match
    promoted = [_pure_finding(fid="f1", technique_ids=["T9001", "T1234"])]

    flagged = triage.harmful_suppressions([match_a, match_b], ["rule_a", "rule_b"], promoted)
    assert flagged == ["rule_a"]


def test_harmful_suppressions_no_match_returns_empty():
    """When no active rule covers any promoted finding, nothing is flagged."""
    match = SuppressionMatch(technique_ids=["T0000"])
    promoted = [_pure_finding(fid="f1", technique_ids=["T1234"])]

    flagged = triage.harmful_suppressions([match], ["rule_x"], promoted)
    assert flagged == []


def test_harmful_suppressions_multiple_rules_multiple_findings():
    """All rules covering at least one promoted finding are returned, sorted."""
    match_a = SuppressionMatch(technique_ids=["T1"])
    match_b = SuppressionMatch(technique_ids=["T2"])
    match_c = SuppressionMatch(technique_ids=["T3"])  # no promoted finding matches
    promoted = [
        _pure_finding(fid="f1", technique_ids=["T1"]),
        _pure_finding(fid="f2", technique_ids=["T2"]),
    ]

    flagged = triage.harmful_suppressions(
        [match_a, match_b, match_c], ["rule_a", "rule_b", "rule_c"], promoted
    )
    assert flagged == ["rule_a", "rule_b"]


# --------------------------------------------------------------------------- #
# Task 1: harmful_flag flip on promote (DB / service level)
# --------------------------------------------------------------------------- #


async def test_harmful_flag_set_on_promote_suppressed_pattern(
    client: AsyncClient, analyst_token: str, admin_token: str, db_session: AsyncSession
):
    """When a finding with a pattern matching an ACTIVE suppression rule is promoted,
    the rule's harmful_flag is flipped, harmful_reason and harmful_finding_id are set,
    and a 'suppression_flagged_harmful' audit row is written."""
    await _post_decoys(client, analyst_token)

    # Post a finding that gets suppressed by the rule we'll create.
    suppressed_f = await _post_finding(
        client, analyst_token, _finding_body("T1810.901", "WS-HARM-SUPP")
    )
    assert suppressed_f["state"] == "clustered"

    # Create a suppression that matches T1810.901.
    supp_resp = await client.post(
        f"/api/v1/hunt/findings/{suppressed_f['id']}/suppress",
        json={
            "name": "harm test rule",
            "reason": "phase-c harmful detection test",
            "match": {"technique_ids": ["T1810.901"]},
        },
        headers=auth_header(admin_token),
    )
    assert supp_resp.status_code == 201, supp_resp.text
    rule_id = supp_resp.json()["id"]

    # A NEW finding with the SAME technique arrives — it's suppressed.
    new_f = await _post_finding(client, analyst_token, _finding_body("T1810.901", "WS-HARM-NEW"))
    assert new_f["state"] == "suppressed"
    assert new_f["suppressed_by"] == rule_id

    # Now promote a DIFFERENT finding with the same technique (simulating a
    # confirmed-threat case). Since the suppression rule would have matched it,
    # the promote path should flag the rule as harmful.
    real_threat = await _post_finding(
        client, analyst_token, _finding_body("T1810.901", "WS-HARM-REAL")
    )
    # This finding was suppressed — promote it anyway via the direct service call
    # (since the API path for promote_findings only takes non-suppressed findings
    # in normal flow; testing the service level proves the logic without needing
    # a special endpoint).
    # Use the DB session to force-reset its state so it can be promoted via API.
    real_row = await svc.get_finding(db_session, real_threat["id"])
    assert real_row is not None
    real_row.state = "clustered"
    await db_session.commit()

    promo = await client.post(
        "/api/v1/hunt/findings/promote",
        json={"finding_ids": [real_threat["id"]], "title": "Confirmed T1810.901 threat"},
        headers=auth_header(admin_token),
    )
    assert promo.status_code == 201, promo.text

    # Verify the rule was flagged harmful.
    rule_row = (
        await db_session.execute(select(SuppressionRuleRow).where(SuppressionRuleRow.id == rule_id))
    ).scalar_one()
    assert rule_row.harmful_flag is True
    assert rule_row.harmful_finding_id == real_threat["id"]
    assert rule_row.harmful_reason is not None
    assert "T1810.901" in rule_row.harmful_reason or real_threat["id"] in rule_row.harmful_reason

    # Verify audit trail has the harmful-flag entry.
    rows = await _hunt_audit_rows(db_session)
    harmful_rows = [r for r in rows if r.action == "suppression_flagged_harmful"]
    assert len(harmful_rows) == 1
    assert harmful_rows[0].resource == f"suppression:{rule_id}"
    assert harmful_rows[0].details["harmful_finding_id"] == real_threat["id"]
    assert harmful_rows[0].details["investigation_id"] == promo.json()["investigation_id"]


async def test_no_harmful_flag_when_rule_does_not_match_promoted(
    client: AsyncClient, analyst_token: str, admin_token: str, db_session: AsyncSession
):
    """A suppression rule that does NOT match any promoted finding stays un-flagged."""
    await _post_decoys(client, analyst_token)

    # Create a rule for T1811.901.
    first_f = await _post_finding(client, analyst_token, _finding_body("T1811.901", "WS-NOHARM-A"))
    supp_resp = await client.post(
        f"/api/v1/hunt/findings/{first_f['id']}/suppress",
        json={
            "name": "no harm rule",
            "reason": "no harm detection test",
            "match": {"technique_ids": ["T1811.901"]},
        },
        headers=auth_header(admin_token),
    )
    assert supp_resp.status_code == 201
    rule_id = supp_resp.json()["id"]

    # Promote a finding with a DIFFERENT technique — should NOT flag the rule.
    other_f = await _post_finding(client, analyst_token, _finding_body("T1811.999", "WS-NOHARM-B"))
    promo = await client.post(
        "/api/v1/hunt/findings/promote",
        json={"finding_ids": [other_f["id"]]},
        headers=auth_header(admin_token),
    )
    assert promo.status_code == 201

    rule_row = (
        await db_session.execute(select(SuppressionRuleRow).where(SuppressionRuleRow.id == rule_id))
    ).scalar_one()
    assert rule_row.harmful_flag is False
    assert rule_row.harmful_reason is None
    assert rule_row.harmful_finding_id is None


# --------------------------------------------------------------------------- #
# Task 2: over-broad rejected for analyst / senior_analyst
# --------------------------------------------------------------------------- #


async def test_overbroad_suppression_rejected_for_senior_analyst(
    client: AsyncClient, analyst_token: str, admin_token: str
):
    """A broad rule (matches > 50% of recent findings) is 409 even with
    acknowledge_overbroad=True when the caller is a senior_analyst (< IC)."""
    # Seed many findings with the same source so a source-only rule is overbroad.
    for i in range(6):
        await _post_finding(client, analyst_token, _finding_body(f"T1901.{i:03d}", f"WS-OB-{i}"))

    # admin_token is admin role so we need a senior_analyst token.
    # We'll create one directly.
    from btagent_backend.auth.jwt import create_token_pair

    sa_token = create_token_pair(
        "usr_sa_test", "sa_test_user", "senior_analyst", org_id=DEFAULT_ORG_ID
    ).access_token

    first = await _post_finding(client, analyst_token, _finding_body("T1901.700", "WS-OB-REJ"))
    resp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "overbroad senior",
            "reason": "broad rule attempt by senior analyst",
            "match": {"source": "hunt_pack"},  # matches all hunt_pack findings -> overbroad
            "acknowledge_overbroad": True,
        },
        headers=auth_header(sa_token),
    )
    # senior_analyst cannot override overbroad — must still be 409.
    assert resp.status_code == 409, resp.text


async def test_overbroad_suppression_rejected_for_analyst_without_ack(
    client: AsyncClient, analyst_token: str, admin_token: str
):
    """An overbroad rule without acknowledge_overbroad=True is always rejected."""
    for i in range(6):
        await _post_finding(client, analyst_token, _finding_body(f"T1902.{i:03d}", f"WS-NOACK-{i}"))
    first = await _post_finding(client, analyst_token, _finding_body("T1902.700", "WS-NOACK-X"))

    resp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "overbroad no ack",
            "reason": "no acknowledgment attempt",
            "match": {"source": "hunt_pack"},
            "acknowledge_overbroad": False,
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 409, resp.text


# --------------------------------------------------------------------------- #
# Task 2: over-broad allowed for IC with acknowledgment + audited
# --------------------------------------------------------------------------- #


async def test_overbroad_allowed_for_ic_with_acknowledgment(
    client: AsyncClient, analyst_token: str, ic_token: str, db_session: AsyncSession
):
    """When acknowledge_overbroad=True and the caller is incident_commander,
    the overbroad gate is passed, the rule is created, and an audit row records
    the override (overbroad_acknowledged, overbroad_reason, approver_role)."""
    # Seed enough hunt_pack findings to make a source-only rule overbroad.
    for i in range(6):
        await _post_finding(client, analyst_token, _finding_body(f"T1903.{i:03d}", f"WS-ICACK-{i}"))

    first = await _post_finding(client, analyst_token, _finding_body("T1903.700", "WS-ICACK-X"))

    resp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "ic overbroad ack",
            "reason": "IC acknowledged overbroad for mass-suppress maintenance",
            "match": {"source": "hunt_pack"},  # overbroad: matches everything
            "acknowledge_overbroad": True,
        },
        headers=auth_header(ic_token),
    )
    assert resp.status_code == 201, resp.text
    rule = resp.json()
    assert rule["state"] == "active"

    # The audit trail must record the override.
    rows = await _hunt_audit_rows(db_session)
    suppress_rows = [r for r in rows if r.action == "suppress"]
    assert len(suppress_rows) == 1
    details = suppress_rows[0].details
    assert details.get("overbroad_acknowledged") is True
    assert "overbroad_reason" in details
    assert details.get("approver_role") == "incident_commander"


async def test_overbroad_allowed_for_admin_with_acknowledgment(
    client: AsyncClient, analyst_token: str, admin_token: str, db_session: AsyncSession
):
    """admin role can also override overbroad with acknowledgment."""
    for i in range(6):
        await _post_finding(client, analyst_token, _finding_body(f"T1904.{i:03d}", f"WS-ADACK-{i}"))
    first = await _post_finding(client, analyst_token, _finding_body("T1904.700", "WS-ADACK-X"))

    resp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "admin overbroad ack",
            "reason": "admin acknowledged overbroad",
            "match": {"source": "hunt_pack"},
            "acknowledge_overbroad": True,
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    rows = await _hunt_audit_rows(db_session)
    suppress_rows = [r for r in rows if r.action == "suppress"]
    assert suppress_rows[0].details.get("overbroad_acknowledged") is True
    assert suppress_rows[0].details.get("approver_role") == "admin"


async def test_overbroad_suppression_appears_in_list(
    client: AsyncClient, analyst_token: str, ic_token: str, db_session: AsyncSession
):
    """An IC-overridden overbroad rule appears in the suppression list and
    the response includes harmful_flag=False (not yet triggered)."""
    for i in range(6):
        await _post_finding(client, analyst_token, _finding_body(f"T1905.{i:03d}", f"WS-LIST-{i}"))
    first = await _post_finding(client, analyst_token, _finding_body("T1905.700", "WS-LIST-X"))

    resp = await client.post(
        f"/api/v1/hunt/findings/{first['id']}/suppress",
        json={
            "name": "list test rule",
            "reason": "list test",
            "match": {"source": "hunt_pack"},
            "acknowledge_overbroad": True,
        },
        headers=auth_header(ic_token),
    )
    assert resp.status_code == 201
    rule_id = resp.json()["id"]

    list_resp = await client.get("/api/v1/hunt/suppressions", headers=auth_header(analyst_token))
    assert list_resp.status_code == 200
    items = {r["id"]: r for r in list_resp.json()["items"]}
    assert rule_id in items
    rule_data = items[rule_id]
    assert rule_data["harmful_flag"] is False
    assert rule_data["harmful_reason"] is None
    assert rule_data["harmful_finding_id"] is None


# --------------------------------------------------------------------------- #
# Task 2: service-level unit test (no HTTP)
# --------------------------------------------------------------------------- #


async def test_create_suppression_overbroad_rejects_without_role(
    db_session: AsyncSession,
):
    """Service: overbroad with acknowledge_overbroad=True but no role → still raises."""
    from btagent_backend.services.hunt_triage_service import (
        OverbroadSuppressionError,
        create_suppression,
    )

    # Seed 10 findings so the source-only match is overbroad.
    for i in range(10):
        await svc.record_finding(
            db_session,
            org_id=DEFAULT_ORG_ID,
            source="hunt_pack",
            domain="sigma",
            title=f"OB svc {i}",
            technique_ids=[f"T1950.{i:03d}"],
        )
    await db_session.commit()

    with pytest.raises(OverbroadSuppressionError):
        await create_suppression(
            db_session,
            org_id=DEFAULT_ORG_ID,
            name="svc overbroad",
            reason="svc test",
            match=SuppressionMatch(source=HuntSource.HUNT_PACK),
            created_by=None,
            acknowledge_overbroad=True,
            caller_role=None,  # no role → rejected
        )


async def test_create_suppression_overbroad_allowed_for_ic_role(
    db_session: AsyncSession,
):
    """Service: overbroad with acknowledge_overbroad=True and IC role → allowed."""
    from btagent_backend.services.hunt_triage_service import create_suppression

    for i in range(10):
        await svc.record_finding(
            db_session,
            org_id=DEFAULT_ORG_ID,
            source="hunt_pack",
            domain="sigma",
            title=f"OB svc IC {i}",
            technique_ids=[f"T1951.{i:03d}"],
        )
    await db_session.commit()

    rule, _ = await create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name="svc ic overbroad",
        reason="IC override at service level",
        match=SuppressionMatch(source=HuntSource.HUNT_PACK),
        created_by=None,
        acknowledge_overbroad=True,
        caller_role="incident_commander",
    )
    assert rule.state == "active"
    # Not harmful yet (no promotion happened).
    assert rule.harmful_flag is False
