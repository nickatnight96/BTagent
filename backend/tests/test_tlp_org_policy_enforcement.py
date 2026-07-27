"""Org TLP policies actually govern real egress (EPIC-7 UC-7.2 runtime half).

The policy registry shipped with storage, an API and a pure evaluator, but
nothing consulted it on a live egress — ``evaluate_egress_policy`` was
reachable only from the dry-run ``POST /tlp-policies/evaluate``. A CISO could
write "deny stix_export of AMBER", watch the endpoint agree, and watch the
export succeed anyway.

These tests pin the two halves of the fix, and the asymmetry between them
matters more than either alone:

* a ``deny`` policy now refuses a real export — the gap that's closed;
* an ``allow`` policy still does **not** let TLP:RED out — the gap that is
  deliberately *left* closed, because honouring a permit would widen a
  default-deny gate. If someone later wires ALLOW through, the test named
  ``test_an_allow_policy_still_cannot_widen_the_red_gate`` is the one that
  should stop them and force the decision to be made explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from btagent_shared.security import TLPViolation
from btagent_shared.security.tlp_policy import (
    TLPViolationEvent,
    clear_violation_sink,
    set_violation_sink,
)
from btagent_shared.types.config import TLP
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    InvestigationRow,
    OrganizationRow,
    TLPPolicyRow,
)
from btagent_backend.services.tlp_egress_guard import assert_org_policy_allows_egress


@pytest_asyncio.fixture(autouse=True)
async def _isolate_policies(db_session: AsyncSession):
    """Clear tlp_policies around every test.

    The suite shares one in-memory DB and ``db_session`` only rolls back, so a
    committed deny policy would otherwise leak forward and start refusing
    exports in unrelated tests.
    """
    await db_session.execute(delete(TLPPolicyRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(TLPPolicyRow))
    await db_session.commit()


async def _add_policy(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    action: str = "deny",
    egress_kinds: list[str] | None = None,
    applies_to_tlp: list[str] | None = None,
    valid_until: datetime | None = None,
) -> TLPPolicyRow:
    row = TLPPolicyRow(
        id=generate_id("tpol"),
        org_id=org_id,
        action=action,
        egress_kinds=egress_kinds if egress_kinds is not None else [],
        applies_to_tlp=applies_to_tlp if applies_to_tlp is not None else [],
        downgrade_to=None,
        approver_id="ciso",
        rationale="test policy",
        valid_until=valid_until,
        # FKs users.id — the policy fixtures aren't testing authorship.
        created_by=None,
    )
    db.add(row)
    await db.commit()
    return row


async def _fresh_org(db: AsyncSession, tag: str) -> str:
    """Create a real org row — ``tlp_policies.org_id`` FKs ``organizations.id``."""
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name=f"TLP {tag}", created_at=datetime.now(UTC)))
    await db.commit()
    return org_id


async def _seed_investigation(
    db: AsyncSession, *, tlp_level: str, org_id: str = DEFAULT_ORG_ID, assigned_to: str
) -> InvestigationRow:
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=org_id,
        title="Policy Case",
        description="policy enforcement fixture",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level=tlp_level,
        assigned_to=assigned_to,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db.add(inv)
    await db.commit()
    return inv


# --------------------------------------------------------------------------- #
# The guard itself
# --------------------------------------------------------------------------- #


async def test_a_deny_policy_refuses_an_egress_the_baseline_would_allow(
    db_session: AsyncSession,
):
    """The gap being closed: AMBER is fine by the baseline, denied by policy."""
    await _add_policy(db_session, egress_kinds=["stix_export"], applies_to_tlp=[TLP.AMBER.value])
    with pytest.raises(TLPViolation):
        await assert_org_policy_allows_egress(
            db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
        )


async def test_no_policy_leaves_the_egress_alone(db_session: AsyncSession):
    """With an empty registry the guard is a no-op — it never invents a denial."""
    await assert_org_policy_allows_egress(
        db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
    )


async def test_a_deny_for_another_channel_does_not_bleed_across(db_session: AsyncSession):
    """Matching is conjunctive: a report_export deny must not stop a STIX export."""
    await _add_policy(db_session, egress_kinds=["report_export"], applies_to_tlp=[TLP.AMBER.value])
    await assert_org_policy_allows_egress(
        db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
    )


async def test_another_tenants_deny_does_not_govern_this_org(db_session: AsyncSession):
    """Policies are org-scoped — one tenant cannot restrict another's egress."""
    other = await _fresh_org(db_session, "other-tenant")
    await _add_policy(db_session, org_id=other, egress_kinds=["stix_export"])
    await assert_org_policy_allows_egress(
        db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
    )


async def test_an_expired_deny_stops_applying(db_session: AsyncSession):
    """A lapsed policy must not keep refusing egress after its validity ends."""
    await _add_policy(
        db_session,
        egress_kinds=["stix_export"],
        applies_to_tlp=[TLP.AMBER.value],
        valid_until=datetime.now(UTC) - timedelta(days=1),
    )
    await assert_org_policy_allows_egress(
        db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
    )


async def test_an_unparseable_classification_fails_closed(db_session: AsyncSession):
    """Garbage resolves to RED, so a RED-scoped deny still catches it.

    A typo in a classification must not buy a laxer policy match than the
    operator intended.
    """
    await _add_policy(db_session, egress_kinds=["stix_export"], applies_to_tlp=[TLP.RED.value])
    with pytest.raises(TLPViolation):
        await assert_org_policy_allows_egress(
            db_session, org_id=DEFAULT_ORG_ID, tlp="grün", egress_kind="stix_export"
        )


async def test_the_violation_event_names_the_policy_that_stopped_it(
    db_session: AsyncSession,
):
    """A ledger row saying "something blocked this" is useless as evidence."""
    policy = await _add_policy(
        db_session, egress_kinds=["stix_export"], applies_to_tlp=[TLP.AMBER.value]
    )
    seen: list[TLPViolationEvent] = []
    set_violation_sink(seen.append)
    try:
        with pytest.raises(TLPViolation):
            await assert_org_policy_allows_egress(
                db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
            )
    finally:
        clear_violation_sink()

    assert len(seen) == 1
    assert seen[0].matched_policy_id == policy.id
    assert seen[0].org_id == DEFAULT_ORG_ID
    assert seen[0].egress_kind == "stix_export"


async def test_a_policy_lookup_failure_does_not_break_a_cleared_egress(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    """A DB blip is the absence of a deny signal, not the presence of one.

    By this point the baseline gate has already approved the egress, so
    failing here would only break exports the system permitted before this
    layer existed. It is logged loudly and allowed through.
    """
    from btagent_backend.services import tlp_egress_guard

    async def _boom(self, **kwargs):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(tlp_egress_guard.TLPPolicyService, "evaluate", _boom, raising=True)
    await assert_org_policy_allows_egress(
        db_session, org_id=DEFAULT_ORG_ID, tlp="amber", egress_kind="stix_export"
    )


# --------------------------------------------------------------------------- #
# The direction that stays closed
# --------------------------------------------------------------------------- #


async def test_an_allow_policy_still_cannot_widen_the_red_gate(db_session: AsyncSession):
    """An ALLOW for RED is inert — the guard never acts on a permit.

    This is deliberate, not an oversight: honouring it would widen the
    default-deny gate protecting TLP:RED. The guard is structurally incapable
    of it (it only ever raises), so the shared baseline keeps the final say.
    """
    await _add_policy(
        db_session,
        action="allow",
        egress_kinds=["stix_export"],
        applies_to_tlp=[TLP.RED.value],
    )
    # The guard permits — but only because it never blocks on an allow...
    await assert_org_policy_allows_egress(
        db_session, org_id=DEFAULT_ORG_ID, tlp="red", egress_kind="stix_export"
    )
    # ...and the baseline gate, which runs first in every real call site, is
    # untouched by the policy and still refuses RED.
    from btagent_shared.security import assert_tlp_allows_egress

    with pytest.raises(TLPViolation):
        assert_tlp_allows_egress([], "stix_export", classification_ctx="red")


# --------------------------------------------------------------------------- #
# Route wiring — the three egress endpoints
# --------------------------------------------------------------------------- #


async def test_stix_export_route_403s_on_a_deny_policy(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    inv = await _seed_investigation(db_session, tlp_level="amber", assigned_to=sample_user.id)
    url = f"/api/v1/iocs/export?investigation_id={inv.id}&tlp_level=amber"

    ok = await client.get(url, headers=auth_header(analyst_token))
    assert ok.status_code == 200, ok.text

    await _add_policy(db_session, egress_kinds=["stix_export"], applies_to_tlp=[TLP.AMBER.value])
    denied = await client.get(url, headers=auth_header(analyst_token))
    assert denied.status_code == 403, denied.text
    assert "stix_export" in denied.json()["detail"]


async def test_report_export_route_403s_on_a_deny_policy(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    inv = await _seed_investigation(db_session, tlp_level="amber", assigned_to=sample_user.id)
    await _add_policy(db_session, egress_kinds=["report_export"], applies_to_tlp=[TLP.AMBER.value])
    resp = await client.get(
        f"/api/v1/reports/{inv.id}/export?format=pdf", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 403, resp.text
    assert "report_export" in resp.json()["detail"]


async def test_knowledge_ingest_route_403s_on_a_deny_policy(
    client: AsyncClient, admin_token: str, db_session: AsyncSession
):
    # knowledge:ingest is senior_analyst+; admin outranks it.
    await _add_policy(
        db_session, egress_kinds=["knowledge_ingest"], applies_to_tlp=[TLP.AMBER.value]
    )
    resp = await client.post(
        "/api/v1/knowledge/ingest",
        json={
            "title": "Restricted runbook",
            "content": "steps",
            "source_type": "runbook",
            "classification": "amber",
        },
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 403, resp.text
    assert "knowledge_ingest" in resp.json()["detail"]
