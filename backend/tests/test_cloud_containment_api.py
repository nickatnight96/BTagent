"""Cloud IAM containment loop (#117 Phase C bullet 2) — promotion → HITL → #106.

End-to-end over the HTTP layer:

* promoting a cloud IAM/STS finding attaches INERT containment proposals to the
  investigation (nothing executed, nothing decided);
* accept is gated by the EXISTING #106 containment execute path and therefore
  inherits every one of its guardrails:
    - ``containment:execute`` RBAC (an analyst / senior analyst is refused),
    - the approved-flag second gate (403 + audited denial, proposal NOT consumed),
    - org never-touch safelist screened before dispatch (audited denial),
    - the always-on account-root structural guard,
    - an audit row on every execute AND every denial,
    - mock-by-default dispatch (``is_mock`` on every tool response);
* org-scoping: another tenant cannot read, accept, or reject the proposal, and
  one org's safelist does not govern another's.

Every exact-COUNT assertion is scoped to a dedicated per-test org
(``generate_id("org")``) so it is immune to rows other tests leave behind in the
session-scoped in-memory SQLite DB.
"""

from __future__ import annotations

from datetime import UTC, datetime

from btagent_shared.types.hunt import HuntDomain
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import AuditLogRow, InvestigationRow, OrganizationRow, UserRow
from btagent_backend.db.models_hunt import HuntFindingRow

# Mirrors agents/tests/fixtures/cloud/iam_fixtures.py — the backend package
# cannot import the agents test tree, so the ARNs are restated here.
_ACCOUNT = "111111111111"
_ACTOR_ARN = f"arn:aws:iam::{_ACCOUNT}:assumed-role/AttackerRole/session9"
_BACKDOOR_ROLE = f"arn:aws:iam::{_ACCOUNT}:role/BackdoorRole"
_BREAK_GLASS_ROLE = f"arn:aws:iam::{_ACCOUNT}:role/BreakGlassIncidentRole"
_ROOT_PRINCIPAL = f"arn:aws:iam::{_ACCOUNT}:root"


# --------------------------------------------------------------------------- #
# Seeding helpers
# --------------------------------------------------------------------------- #


async def _seed_user(
    db_session: AsyncSession, *, role: str, org_id: str | None = None
) -> tuple[str, str, str]:
    """Create a fresh org (unless given) + a user in ``role``; return (org, user, token)."""
    if org_id is None:
        org_id = generate_id("org")
        db_session.add(
            OrganizationRow(id=org_id, name=f"Cloud IR {org_id}", created_at=datetime.now(UTC))
        )
    user_id = generate_id("usr")
    db_session.add(
        UserRow(
            id=user_id,
            org_id=org_id,
            username=f"{role}_{user_id}",
            email=f"{user_id}@btagent.test",
            password_hash=hash_password("Cloud-P@ss-123!"),
            role=role,
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    token = create_token_pair(user_id, f"{role}_{user_id}", role, org_id=org_id).access_token
    return org_id, user_id, token


def _iam_finding(
    *,
    org_id: str,
    event_name: str = "PutRolePolicy",
    role_name: str = "BackdoorRole",
    policy_name: str = "AdminAccess",
    detection: str = "iam_persistence",
    title: str = "IAM persistence activity: PutRolePolicy",
) -> HuntFindingRow:
    """A cloud finding with the evidence shape ``detect_iam_persistence`` emits."""
    return HuntFindingRow(
        id=generate_id("hfnd"),
        org_id=org_id,
        source="cloud",
        domain=HuntDomain.CLOUD.value,
        title=title,
        description="",
        severity="high",
        confidence=0.85,
        state="new",
        technique_ids=["T1098.003", "T1098.001"],
        entities=[
            {"kind": "cloud_identity", "value": _ACTOR_ARN},
            {"kind": "iam_resource", "value": role_name},
        ],
        observables=[],
        evidence={
            "detection": detection,
            "event_name": event_name,
            "event_time": "2026-06-18T12:01:00Z",
            "aws_region": "us-east-1",
            "provider": "aws",
            "request_parameters": {"roleName": role_name, "policyName": policy_name},
        },
        signature="",
        created_at=datetime.now(UTC),
    )


async def _promote(
    client: AsyncClient, token: str, db_session: AsyncSession, rows: list[HuntFindingRow]
) -> str:
    for row in rows:
        db_session.add(row)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/hunt/findings/promote",
        headers=auth_header(token),
        json={"finding_ids": [r.id for r in rows]},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["investigation_id"]


def _url(investigation_id: str, suffix: str = "") -> str:
    return f"/api/v1/cloud/investigations/{investigation_id}/containment-proposal{suffix}"


async def _audit_rows(db_session: AsyncSession, *, org_id: str) -> list[AuditLogRow]:
    result = await db_session.execute(
        select(AuditLogRow).where(AuditLogRow.org_id == org_id).order_by(AuditLogRow.seq.asc())
    )
    return list(result.scalars().all())


def _executed(rows: list[AuditLogRow]) -> list[AuditLogRow]:
    """Audit rows recording an actual containment dispatch (not promotion noise)."""
    return [r for r in rows if r.action.startswith("execute:") and r.outcome == "success"]


async def _add_safelist(client: AsyncClient, token: str, *, entry_type: str, value: str) -> None:
    resp = await client.post(
        "/api/v1/containment/safelist",
        json={"entry_type": entry_type, "value": value, "reason": "never touch"},
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.text


# --------------------------------------------------------------------------- #
# Promotion attaches INERT proposals
# --------------------------------------------------------------------------- #


async def test_promotion_attaches_inert_containment_proposals(
    client: AsyncClient, db_session: AsyncSession
):
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])

    resp = await client.get(_url(inv_id), headers=auth_header(token))
    assert resp.status_code == 200, resp.text
    proposal = resp.json()

    assert proposal["status"] == "proposed"
    assert proposal["decided_by"] is None
    assert len(proposal["actions"]) == 1
    action = proposal["actions"][0]
    assert action["action_type"] == "detach_policy"
    assert action["target"] == _BACKDOOR_ROLE
    assert action["connector"] == "aws_iam"
    # Inert: nothing ran, nothing was audited against the action yet.
    assert action["status"] == "proposed"
    assert action["audit_id"] is None
    assert action["outcome"] == ""

    # And no containment audit row exists yet — promotion executes nothing.
    rows = await _audit_rows(db_session, org_id=org_id)
    assert [r for r in rows if r.category == "containment"] == []


async def test_non_iam_cloud_promotion_has_no_proposal(
    client: AsyncClient, db_session: AsyncSession
):
    """A shadow-workload governance finding is not IAM containment material (404)."""
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    row = _iam_finding(
        org_id=org_id,
        detection="shadow_workload",
        title="Shadow agentic workload discovered",
    )
    inv_id = await _promote(client, token, db_session, [row])
    resp = await client.get(_url(inv_id), headers=auth_header(token))
    assert resp.status_code == 404, resp.text


# --------------------------------------------------------------------------- #
# Gate 1 — containment:execute RBAC
# --------------------------------------------------------------------------- #


async def test_accept_requires_containment_execute_scope(
    client: AsyncClient, db_session: AsyncSession
):
    """A senior analyst may read the proposal but may not run it."""
    org_id, _ic_id, ic_token = await _seed_user(db_session, role="incident_commander")
    _org, _sid, senior_token = await _seed_user(db_session, role="senior_analyst", org_id=org_id)
    inv_id = await _promote(client, ic_token, db_session, [_iam_finding(org_id=org_id)])

    # Read is analyst-level (hunt:view) — allowed.
    read = await client.get(_url(inv_id), headers=auth_header(senior_token))
    assert read.status_code == 200, read.text

    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": True, "rationale": "contain it"},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 403, resp.text

    # Nothing executed and the proposal is untouched.
    after = await client.get(_url(inv_id), headers=auth_header(ic_token))
    assert after.json()["status"] == "proposed"
    assert after.json()["actions"][0]["status"] == "proposed"
    assert _executed(await _audit_rows(db_session, org_id=org_id)) == []


async def test_accept_requires_auth(client: AsyncClient, db_session: AsyncSession):
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])
    resp = await client.post(_url(inv_id, "/accept"), json={"approved": True})
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Gate 2 — the approved flag (HITL half of the double gate)
# --------------------------------------------------------------------------- #


async def test_accept_without_approved_is_denied_and_audited(
    client: AsyncClient, db_session: AsyncSession
):
    """Holding the scope is not enough: an un-approved accept runs nothing.

    The refusal is a first-class audited fact written by the #106 service, and
    it must NOT consume the proposal — it stays ``proposed`` so the analyst can
    still make a real decision.
    """
    org_id, user_id, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])

    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": False, "rationale": "oops"},
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["status"] == "proposed"  # NOT consumed
    assert body["actions"][0]["status"] == "denied"
    assert "approved" in body["actions"][0]["message"].lower()

    rows = await _audit_rows(db_session, org_id=org_id)
    denials = [r for r in rows if r.outcome == "denied" and r.action == "execute:detach_policy"]
    assert len(denials) == 1
    assert denials[0].category == "containment"
    assert denials[0].details.get("approver_id") == user_id
    assert _executed(rows) == []

    # Still decidable afterwards — the denial did not burn the proposal.
    again = await client.get(_url(inv_id), headers=auth_header(token))
    assert again.json()["status"] == "proposed"


# --------------------------------------------------------------------------- #
# Gate 3 — org never-touch safelist, screened BEFORE dispatch
# --------------------------------------------------------------------------- #


async def test_safelisted_principal_refused_with_audited_denial(
    client: AsyncClient, db_session: AsyncSession
):
    org_id, user_id, token = await _seed_user(db_session, role="incident_commander")
    await _add_safelist(client, token, entry_type="principal", value=_BREAK_GLASS_ROLE)

    row = _iam_finding(
        org_id=org_id,
        event_name="UpdateAssumeRolePolicy",
        role_name="BreakGlassIncidentRole",
        title="IAM persistence activity: UpdateAssumeRolePolicy",
    )
    inv_id = await _promote(client, token, db_session, [row])

    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": True, "rationale": "contain the trust mutation"},
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["status"] == "proposed"
    action = body["actions"][0]
    assert action["target"] == _BREAK_GLASS_ROLE
    assert action["status"] == "denied"
    assert "safelist" in action["message"].lower()
    assert action["audit_id"]

    rows = await _audit_rows(db_session, org_id=org_id)
    denials = [r for r in rows if r.outcome == "denied" and r.action == "execute:revoke_role"]
    assert len(denials) == 1
    assert "safelist" in denials[0].details.get("reason", "").lower()
    assert denials[0].details.get("approver_id") == user_id
    # The refusal happened BEFORE dispatch — no tool response was recorded.
    assert "tool_response" not in denials[0].details
    assert _executed(rows) == []


async def test_account_root_principal_refused_without_any_org_entry(
    client: AsyncClient, db_session: AsyncSession
):
    """The account root is structurally never-touch: freezing it locks out responders."""
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    row = _iam_finding(org_id=org_id)
    # Rewrite the evidence so the proposal targets the account root verbatim.
    row.evidence = {
        **row.evidence,
        "detection": "cross_account_trust_abuse",
        "identity_arn": _ROOT_PRINCIPAL,
        "external_trustees": ["arn:aws:iam::999999999999:root"],
    }
    inv_id = await _promote(client, token, db_session, [row])

    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": True},
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["actions"][0]["target"] == _ROOT_PRINCIPAL

    rows = await _audit_rows(db_session, org_id=org_id)
    assert [r.outcome for r in rows if r.category == "containment"].count("denied") >= 1
    assert _executed(rows) == []


# --------------------------------------------------------------------------- #
# Happy path — mock dispatch, audited execute, idempotent decision
# --------------------------------------------------------------------------- #


async def test_accept_executes_through_the_106_path_and_audits(
    client: AsyncClient, db_session: AsyncSession
):
    org_id, user_id, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])

    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": True, "rationale": "confirmed backdoor policy"},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["decided_by"] == user_id
    action = body["actions"][0]
    assert action["status"] == "executed"
    assert action["outcome"] == "success"
    assert action["audit_id"]

    rows = await _audit_rows(db_session, org_id=org_id)
    executes = [r for r in rows if r.action == "execute:detach_policy"]
    assert len(executes) == 1
    assert executes[0].category == "containment"
    assert executes[0].outcome == "success"
    assert executes[0].details.get("approver_id") == user_id
    # Mock-by-default: the dispatch never left the process.
    assert executes[0].details.get("mock") is True
    assert executes[0].details.get("tool_response", {}).get("is_mock") is True

    # A decision-level summary row accompanies the per-action rows.
    summary = [r for r in rows if r.action == "cloud_containment_accept"]
    assert len(summary) == 1
    assert summary[0].details.get("executed_count") == 1

    # Idempotent: a second accept cannot re-execute.
    again = await client.post(
        _url(inv_id, "/accept"), json={"approved": True}, headers=auth_header(token)
    )
    assert again.status_code == 409, again.text
    assert len(_executed(await _audit_rows(db_session, org_id=org_id))) == 1


async def test_reject_records_the_decision_and_executes_nothing(
    client: AsyncClient, db_session: AsyncSession
):
    org_id, user_id, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])

    resp = await client.post(
        _url(inv_id, "/reject"),
        json={"rationale": "expected change-managed policy update"},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "rejected"
    assert resp.json()["decided_by"] == user_id

    rows = await _audit_rows(db_session, org_id=org_id)
    assert [r for r in rows if r.action.startswith("execute:")] == []
    assert len([r for r in rows if r.action == "cloud_containment_reject"]) == 1

    # Rejected proposals cannot then be accepted.
    accept = await client.post(
        _url(inv_id, "/accept"), json={"approved": True}, headers=auth_header(token)
    )
    assert accept.status_code == 409, accept.text


# --------------------------------------------------------------------------- #
# Org scoping
# --------------------------------------------------------------------------- #


async def test_proposal_is_org_scoped(client: AsyncClient, db_session: AsyncSession):
    org_a, _ua, token_a = await _seed_user(db_session, role="incident_commander")
    _org_b, _ub, token_b = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token_a, db_session, [_iam_finding(org_id=org_a)])

    # Org B sees a 404 (not a 403) — the id must not be probeable across tenants.
    assert (await client.get(_url(inv_id), headers=auth_header(token_b))).status_code == 404
    for suffix in ("/accept", "/reject"):
        resp = await client.post(
            _url(inv_id, suffix), json={"approved": True}, headers=auth_header(token_b)
        )
        assert resp.status_code == 404, resp.text

    # Org A's proposal is untouched by B's attempts.
    mine = await client.get(_url(inv_id), headers=auth_header(token_a))
    assert mine.status_code == 200
    assert mine.json()["status"] == "proposed"


async def test_principal_safelist_is_org_scoped(client: AsyncClient, db_session: AsyncSession):
    """One tenant's never-touch principal must not govern another tenant."""
    org_a, _ua, token_a = await _seed_user(db_session, role="incident_commander")
    org_b, _ub, token_b = await _seed_user(db_session, role="incident_commander")
    await _add_safelist(client, token_a, entry_type="principal", value=_BACKDOOR_ROLE)

    # Org A refuses the action against its safelisted principal.
    inv_a = await _promote(client, token_a, db_session, [_iam_finding(org_id=org_a)])
    denied = await client.post(
        _url(inv_a, "/accept"), json={"approved": True}, headers=auth_header(token_a)
    )
    assert denied.status_code == 403, denied.text

    # Org B, with no such entry, executes the identical action.
    inv_b = await _promote(client, token_b, db_session, [_iam_finding(org_id=org_b)])
    allowed = await client.post(
        _url(inv_b, "/accept"), json={"approved": True}, headers=auth_header(token_b)
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["actions"][0]["status"] == "executed"

    # Org B cannot see org A's safelist entry either.
    listing = await client.get("/api/v1/containment/safelist", headers=auth_header(token_b))
    assert listing.status_code == 200
    assert all(e["org_id"] == org_b for e in listing.json())


# --------------------------------------------------------------------------- #
# Partial accept — a named subset only
# --------------------------------------------------------------------------- #


async def test_partial_accept_runs_only_the_named_actions(
    client: AsyncClient, db_session: AsyncSession
):
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    rows = [
        _iam_finding(org_id=org_id),
        _iam_finding(
            org_id=org_id,
            event_name="CreateAccessKey",
            role_name="svc-backup",
            title="IAM persistence activity: CreateAccessKey",
        ),
    ]
    inv_id = await _promote(client, token, db_session, rows)

    proposal = (await client.get(_url(inv_id), headers=auth_header(token))).json()
    assert len(proposal["actions"]) == 2
    chosen = proposal["actions"][0]["id"]

    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": True, "action_ids": [chosen]},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    statuses = {a["id"]: a["status"] for a in resp.json()["actions"]}
    assert statuses[chosen] == "executed"
    assert [s for aid, s in statuses.items() if aid != chosen] == ["proposed"]

    executes = [
        r for r in await _audit_rows(db_session, org_id=org_id) if r.action.startswith("execute:")
    ]
    assert len(executes) == 1


async def test_unknown_action_id_is_404(client: AsyncClient, db_session: AsyncSession):
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])
    resp = await client.post(
        _url(inv_id, "/accept"),
        json={"approved": True, "action_ids": ["cca_999"]},
        headers=auth_header(token),
    )
    assert resp.status_code == 404, resp.text


# --------------------------------------------------------------------------- #
# Investigation config carries the proposal (the seam promotion writes)
# --------------------------------------------------------------------------- #


async def test_proposal_is_persisted_on_the_investigation_config(
    client: AsyncClient, db_session: AsyncSession
):
    org_id, _uid, token = await _seed_user(db_session, role="incident_commander")
    inv_id = await _promote(client, token, db_session, [_iam_finding(org_id=org_id)])

    inv = (
        await db_session.execute(select(InvestigationRow).where(InvestigationRow.id == inv_id))
    ).scalar_one()
    stored = (inv.config or {}).get("cloud_containment_proposal")
    assert isinstance(stored, dict)
    assert stored["status"] == "proposed"
    assert stored["actions"][0]["target"] == _BACKDOOR_ROLE
