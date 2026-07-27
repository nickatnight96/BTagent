"""Audit-ledger writes are stamped with the *writing* tenant (EPIC-7).

GH #385 made every audit read surface tenant-scoped
(``get_entries(org_id=user.org_id)``), but no write site passed ``org_id``,
so every entry landed under ``DEFAULT_ORG_ID``. The two halves disagreed:
a non-default tenant's ledger read back empty while its entries piled into
the default org's ledger — the opposite of the isolation #385 intended.

These tests pin both directions of the fix: an entry written by tenant B is
visible to tenant B and *invisible* to the default org. The service-path
case matters most — there the org must come from the row being acted on,
not from the caller.

#434 landed the same fix concurrently and went further, making ``org_id``
a required keyword-only argument on ``record()``. That is the stronger
guarantee — an un-stamped write is now a hard error at call time rather
than a row silently filed under ``DEFAULT_ORG_ID``, where it would be both
hidden from its own tenant and visible to an ``org_default`` admin. The
last test pins that.
"""

from __future__ import annotations

import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import delete

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    AuditLogRow,
    OrganizationRow,
    TLPPolicyRow,
    UserRow,
)
from btagent_backend.db.models_workflow import WorkflowRow
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.workflow_service import soft_delete_workflow
from tests.helpers import auth_header

# A dedicated org for this module. The in-memory test DB is session-scoped
# and committed rows persist, so a second tenant must never be simulated by
# mutating DEFAULT_ORG_ID state — that would bleed into every later test.
TENANT_B = "org_audit_stamp_tenant_b"


@pytest_asyncio.fixture(autouse=True)
async def _isolate(db_session):
    """Clear audit_logs + tlp_policies around each test.

    ``AuditTrail.record`` assigns ``seq = max+1`` while test_audit_trail.py
    numbers from its own counter; leftovers from here collide on the
    ``audit_logs.seq`` unique constraint.
    """
    await db_session.execute(delete(AuditLogRow))
    await db_session.execute(delete(TLPPolicyRow))
    await db_session.commit()
    yield
    await db_session.execute(delete(AuditLogRow))
    await db_session.execute(delete(TLPPolicyRow))
    await db_session.commit()


@pytest_asyncio.fixture()
async def tenant_b_admin(db_session) -> UserRow:
    """An admin belonging to a second tenant."""
    if await db_session.get(OrganizationRow, TENANT_B) is None:
        db_session.add(OrganizationRow(id=TENANT_B, name="Audit Stamp Tenant B"))
        await db_session.flush()
    user = UserRow(
        id=generate_id("usr"),
        org_id=TENANT_B,
        username=f"tenant_b_admin_{generate_id('x')}",
        email=f"{generate_id('x')}@tenant-b.test",
        password_hash=hash_password("Tenant-B-P@ss-123!"),
        role="admin",
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture()
async def tenant_b_token(tenant_b_admin: UserRow) -> str:
    # org_id is a JWT claim, not read back from the user row — it defaults to
    # the default org, so a second-tenant token must state its org explicitly.
    return create_token_pair(
        tenant_b_admin.id,
        tenant_b_admin.username,
        tenant_b_admin.role,
        org_id=TENANT_B,
    ).access_token


async def _entries(db_session, org_id: str) -> list[AuditLogRow]:
    return await AuditTrail(db_session).get_entries(org_id=org_id, limit=100)


# --- API write path -------------------------------------------------------- #


async def test_policy_create_is_stamped_to_the_writing_tenant(
    client: AsyncClient, tenant_b_token: str, db_session
):
    resp = await client.post(
        "/api/v1/tlp-policies",
        json={
            "action": "allow",
            "egress_kinds": ["stix_export"],
            "applies_to_tlp": ["red"],
            "rationale": "Partner ISAC channel.",
        },
        headers=auth_header(tenant_b_token),
    )
    assert resp.status_code == 201, resp.text
    policy_id = resp.json()["id"]

    mine = await _entries(db_session, TENANT_B)
    assert [e.action for e in mine] == ["tlp_policy_created"]
    assert mine[0].resource == policy_id
    assert mine[0].details["policy_action"] == "allow"

    # The default org must not see another tenant's governance events.
    assert await _entries(db_session, DEFAULT_ORG_ID) == []


async def test_policy_revoke_records_the_terms_it_revoked(
    client: AsyncClient, tenant_b_token: str, db_session
):
    """The revoke entry must be self-contained — the row is gone afterwards."""
    created = await client.post(
        "/api/v1/tlp-policies",
        json={
            "action": "downgrade_then_allow",
            "egress_kinds": ["event_emit"],
            "applies_to_tlp": ["red"],
            "downgrade_to": "amber",
            "rationale": "Temporary exception.",
        },
        headers=auth_header(tenant_b_token),
    )
    policy_id = created.json()["id"]

    resp = await client.delete(
        f"/api/v1/tlp-policies/{policy_id}", headers=auth_header(tenant_b_token)
    )
    assert resp.status_code == 204, resp.text

    revoked = [e for e in await _entries(db_session, TENANT_B) if e.action == "tlp_policy_revoked"]
    assert len(revoked) == 1
    details = revoked[0].details
    assert revoked[0].resource == policy_id
    assert details["policy_action"] == "downgrade_then_allow"
    assert details["egress_kinds"] == ["event_emit"]
    assert details["downgrade_to"] == "amber"


async def test_revoking_an_unknown_policy_writes_no_entry(
    client: AsyncClient, tenant_b_token: str, db_session
):
    resp = await client.delete(
        "/api/v1/tlp-policies/tpol_does_not_exist", headers=auth_header(tenant_b_token)
    )
    assert resp.status_code == 404
    assert await _entries(db_session, TENANT_B) == []


# --- service write path ---------------------------------------------------- #


async def test_service_write_takes_the_org_from_the_row_not_the_actor(db_session):
    """A workflow owned by tenant B audits to tenant B, whoever the actor is."""
    workflow = WorkflowRow(
        id=generate_id("wf"),
        name="Tenant B workflow",
        description="",
        org_id=TENANT_B,
    )
    db_session.add(workflow)
    await db_session.flush()

    await soft_delete_workflow(db_session, workflow=workflow, actor="usr_someone_else")
    await db_session.commit()

    mine = await _entries(db_session, TENANT_B)
    assert [e.action for e in mine] == ["delete"]
    assert mine[0].resource == f"workflow:{workflow.id}"
    assert await _entries(db_session, DEFAULT_ORG_ID) == []


async def test_an_unstamped_write_is_rejected_outright(db_session):
    """No silent DEFAULT_ORG_ID fallback — omitting the tenant must fail loudly.

    A fallback would file the row under ``org_default``: invisible to the
    tenant whose compliance ledger needs it, and visible to an
    ``org_default`` admin who should never see it. Failing at call time
    makes a missed call site a bug the test suite catches, not a quiet
    mis-attribution nobody notices until an audit.
    """
    import pytest
    from btagent_shared.types.enums import AuditCategory, AuditOutcome

    with pytest.raises(TypeError):
        await AuditTrail(db_session).record(
            actor="system",
            category=AuditCategory.AGENT_ACTION,
            action="untenanted_write",
            resource="res_x",
            outcome=AuditOutcome.SUCCESS,
        )

    assert await _entries(db_session, DEFAULT_ORG_ID) == []
    assert await _entries(db_session, TENANT_B) == []
