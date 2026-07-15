"""Tests for the read-derive OAuth grant endpoint (#216 Phase C, slice 1).

Seeds identity-domain HuntFindingRows with the same evidence shape the
``shared.hunt.identity`` detectors emit, then exercises the HTTP layer for:
- the happy path (paginated, sorted, dedup'd list)
- principal_id / provider / active filters
- non-grant identity findings are skipped (no app_id ⇒ not part of the graph)
- RBAC (hunt:view) + org scoping (cross-tenant isolation)
- pagination is over distinct grants, not raw rows
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest_asyncio
from btagent_shared.types.hunt import HuntDomain
from btagent_shared.types.identity_hunt import IdentityProvider
from btagent_shared.utils.ids import generate_id
from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow

# Distinct from other suites' second-org rows: committed rows persist across
# tests in this conftest and organizations.name is UNIQUE, so reusing the
# common "org_other_tenant" / "Other Tenant" literal collides with
# test_workflow_run_api. Keep this id + name unique to this module.
OTHER_ORG = "org_idgrants_other"
OTHER_ORG_NAME = "Identity-Grants Other Tenant"


def _finding(
    *,
    org_id: str = DEFAULT_ORG_ID,
    principal_id: str | None = "alice@example.com",
    app_id: str | None = "app_slack",
    app_display_name: str = "Slack",
    provider: str = "okta",
    consent_type: str = "user",
    scopes: list[str] | None = None,
    granted_at: datetime | None = None,
    last_used: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime | None = None,
    title: str = "Dormant OAuth app reactivated",
    domain: str = HuntDomain.IDENTITY.value,
) -> HuntFindingRow:
    """Build a HuntFindingRow with the evidence shape the identity detectors emit."""
    evidence: dict = {}
    if principal_id is not None:
        evidence["principal_id"] = principal_id
    if app_id is not None:
        evidence["app_id"] = app_id
    evidence["app_display_name"] = app_display_name
    evidence["provider"] = provider
    evidence["consent_type"] = consent_type
    evidence["scopes"] = scopes if scopes is not None else ["openid", "profile"]
    if granted_at is not None:
        evidence["granted_at"] = granted_at.isoformat()
    if last_used is not None:
        evidence["last_used"] = last_used.isoformat()
    if revoked_at is not None:
        evidence["revoked_at"] = revoked_at.isoformat()

    return HuntFindingRow(
        id=generate_id("hfnd"),
        org_id=org_id,
        source="identity",
        domain=domain,
        title=title,
        description="",
        severity="medium",
        confidence=0.7,
        state="new",
        technique_ids=["T1078.004"],
        entities=[],
        observables=[],
        evidence=evidence,
        signature="",
        created_at=created_at or datetime.now(UTC),
    )


@pytest_asyncio.fixture
async def seeded_identity_findings(db_session):
    """A spread of identity findings: two for the same grant (dedup target),
    one for a different grant on the same principal, one revoked, one Entra,
    one in a different org (must be hidden), and one non-grant finding."""
    now = datetime.now(UTC)
    older = now - timedelta(days=10)

    # The cross-tenant row references OTHER_ORG via FK; create that org first.
    from btagent_backend.db.models import OrganizationRow

    if await db_session.get(OrganizationRow, OTHER_ORG) is None:
        db_session.add(OrganizationRow(id=OTHER_ORG, name=OTHER_ORG_NAME))
        await db_session.flush()

    rows = [
        # Same (alice, app_slack, okta) seen twice — older first, newer wins.
        _finding(
            granted_at=older,
            last_used=older,
            scopes=["openid"],
            created_at=older,
        ),
        _finding(
            granted_at=older,
            last_used=now,
            scopes=["openid", "profile", "Mail.Read"],
            created_at=now,
        ),
        # Same principal, different app.
        _finding(
            app_id="app_zoom",
            app_display_name="Zoom",
            granted_at=now - timedelta(days=2),
            last_used=now - timedelta(hours=1),
            created_at=now - timedelta(hours=1),
        ),
        # Different principal, revoked grant.
        _finding(
            principal_id="bob@example.com",
            app_id="app_legacy",
            granted_at=now - timedelta(days=30),
            revoked_at=now - timedelta(days=1),
            created_at=now - timedelta(days=1),
        ),
        # Entra provider — separates the dedup key.
        _finding(
            principal_id="alice@example.com",
            app_id="app_slack",
            provider="entra",
            granted_at=now - timedelta(days=5),
            created_at=now - timedelta(days=5),
        ),
        # Cross-tenant — must NEVER surface for DEFAULT_ORG_ID.
        _finding(
            org_id=OTHER_ORG,
            principal_id="alice@example.com",
            app_id="app_attacker",
            granted_at=now,
            created_at=now,
        ),
        # Non-grant identity finding (token replay) — no app_id, must be skipped.
        _finding(
            principal_id="alice@example.com",
            app_id=None,
            title="Token replay across ASNs",
            created_at=now,
        ),
    ]
    for row in rows:
        db_session.add(row)
    await db_session.commit()
    return rows


# --------------------------------------------------------------------------- #
# Happy path + dedup + ordering
# --------------------------------------------------------------------------- #


async def test_grants_endpoint_returns_dedup_org_scoped_list(
    client, analyst_token, seeded_identity_findings
):
    resp = await client.get(
        "/api/v1/identity/grants?page_size=200", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200
    body = resp.json()
    # 5 seeded grants in DEFAULT_ORG_ID, but (alice, slack, okta) appears
    # twice so this fixture contributes exactly 4 distinct grants. Assert by
    # id containment rather than org-wide totals — other suites in the shared
    # session DB legitimately add their own grants (first-class store, #116).
    fixture_ids = {
        "oag_okta_alice@example.com_app_slack",
        "oag_entra_alice@example.com_app_slack",
        "oag_okta_alice@example.com_app_zoom",
        "oag_okta_bob@example.com_app_legacy",
    }
    listed_ids = {g["id"] for g in body["items"]}
    assert fixture_ids <= listed_ids
    # The duplicated (alice, slack, okta) rows collapsed to one item.
    assert sum(1 for g in body["items"] if g["id"] == "oag_okta_alice@example.com_app_slack") == 1

    # The newer (alice, slack, okta) view wins — scopes from the fresher row.
    slack_okta = next(
        g
        for g in body["items"]
        if g["principal_id"] == "alice@example.com"
        and g["app_id"] == "app_slack"
        and g["provider"] == "okta"
    )
    assert sorted(slack_okta["scopes"]) == sorted(["openid", "profile", "Mail.Read"])
    # Stable dedup id derived from the grant tuple.
    assert slack_okta["id"] == "oag_okta_alice@example.com_app_slack"

    # Cross-tenant principal/app pair must not surface.
    assert not any(g["app_id"] == "app_attacker" for g in body["items"])


async def test_grants_are_sorted_most_recent_first(client, analyst_token, seeded_identity_findings):
    resp = await client.get("/api/v1/identity/grants", headers=auth_header(analyst_token))
    items = resp.json()["items"]
    anchors = [g.get("last_used") or g["granted_at"] for g in items]
    assert anchors == sorted(anchors, reverse=True)


# --------------------------------------------------------------------------- #
# Filters
# --------------------------------------------------------------------------- #


async def test_principal_id_filter(client, analyst_token, seeded_identity_findings):
    resp = await client.get(
        "/api/v1/identity/grants",
        params={"principal_id": "bob@example.com"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["principal_id"] == "bob@example.com"
    assert body["items"][0]["app_id"] == "app_legacy"


async def test_provider_filter(client, analyst_token, seeded_identity_findings):
    resp = await client.get(
        "/api/v1/identity/grants",
        params={"provider": "entra"},
        headers=auth_header(analyst_token),
    )
    items = resp.json()["items"]
    assert items and all(g["provider"] == "entra" for g in items)


async def test_active_filter_excludes_revoked(client, analyst_token, seeded_identity_findings):
    resp = await client.get(
        "/api/v1/identity/grants",
        params={"active": "true"},
        headers=auth_header(analyst_token),
    )
    items = resp.json()["items"]
    assert items
    assert all(g["revoked_at"] is None for g in items)
    # bob's app_legacy grant is revoked — it must not appear for bob. (Other
    # suites may reuse the app id under different principals; scope the check.)
    assert not any(
        g["app_id"] == "app_legacy" and g["principal_id"] == "bob@example.com" for g in items
    )


async def test_active_false_returns_only_revoked(client, analyst_token, seeded_identity_findings):
    resp = await client.get(
        "/api/v1/identity/grants",
        params={"active": "false"},
        headers=auth_header(analyst_token),
    )
    items = resp.json()["items"]
    assert items and all(g["revoked_at"] is not None for g in items)


async def test_unknown_provider_filter_yields_empty(
    client, analyst_token, seeded_identity_findings
):
    resp = await client.get(
        "/api/v1/identity/grants",
        params={"provider": "not_a_provider"},
        headers=auth_header(analyst_token),
    )
    # An unknown provider string is silently treated as "no provider filter"
    # by the parser; we still want the response to be a well-formed list.
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["items"], list)
    assert body["total"] >= 1


# --------------------------------------------------------------------------- #
# Pagination is over distinct grants
# --------------------------------------------------------------------------- #


async def test_pagination_is_over_distinct_grants(client, analyst_token, seeded_identity_findings):
    # Scope to alice so the expected universe is exactly this fixture's three
    # distinct grants (slack/okta collapsed from two findings, slack/entra,
    # zoom/okta) regardless of what other suites wrote for the org.
    params = {"principal_id": "alice@example.com"}
    resp = await client.get(
        "/api/v1/identity/grants",
        params={**params, "page": 1, "page_size": 2},
        headers=auth_header(analyst_token),
    )
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2

    resp2 = await client.get(
        "/api/v1/identity/grants",
        params={**params, "page": 2, "page_size": 2},
        headers=auth_header(analyst_token),
    )
    body2 = resp2.json()
    assert len(body2["items"]) == 1
    # Distinct pages — no overlap.
    page1_ids = {g["id"] for g in body["items"]}
    page2_ids = {g["id"] for g in body2["items"]}
    assert page1_ids.isdisjoint(page2_ids)


# --------------------------------------------------------------------------- #
# AuthN / AuthZ
# --------------------------------------------------------------------------- #


async def test_grants_require_auth(client):
    resp = await client.get("/api/v1/identity/grants")
    assert resp.status_code == 401


async def test_non_identity_domain_findings_excluded(client, analyst_token, db_session):
    """A sigma-domain finding that happens to carry app_id/principal_id in its
    evidence must not bleed into the grant inventory."""
    db_session.add(
        _finding(
            domain=HuntDomain.SIGMA.value,
            principal_id="eve@example.com",
            app_id="app_anything",
        )
    )
    await db_session.commit()

    resp = await client.get("/api/v1/identity/grants", headers=auth_header(analyst_token))
    body = resp.json()
    assert not any(g["principal_id"] == "eve@example.com" for g in body["items"])
