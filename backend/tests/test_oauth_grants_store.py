"""Tests for the first-class oauth_grants store + ingest writer (#116 follow-up).

- record_finding on an identity-domain finding with a grant tuple upserts an
  ``oauth_grants`` row (the ingest-side write path); non-grant findings and
  non-identity domains don't
- re-observing the same grant refreshes (newest-wins) instead of duplicating;
  revocations propagate
- GET /identity/grants serves the union: read-derive as before, with
  first-class table rows overlaid (table wins per grant tuple) — pre-writer
  findings keep surfacing, writer-era rows are authoritative
- malformed evidence never breaks ingest (fail-open)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.db.models_identity import OAuthGrantRow
from btagent_backend.services import hunt_triage_service as triage_svc

_NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _grant_evidence(
    *,
    principal: str,
    app: str,
    provider: str = "okta",
    scopes: list[str] | None = None,
    revoked_at: datetime | None = None,
    last_used: datetime | None = None,
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "principal_id": principal,
        "app_id": app,
        "provider": provider,
        "app_display_name": f"App {app}",
        "consent_type": "user",
        "scopes": scopes if scopes is not None else ["openid"],
        "granted_at": (_NOW - timedelta(days=30)).isoformat(),
    }
    if last_used is not None:
        ev["last_used"] = last_used.isoformat()
    if revoked_at is not None:
        ev["revoked_at"] = revoked_at.isoformat()
    return ev


async def _record_identity_finding(
    db: AsyncSession, evidence: dict[str, Any], *, domain: str = "identity"
) -> HuntFindingRow:
    row = await triage_svc.record_finding(
        db,
        org_id=DEFAULT_ORG_ID,
        source="identity",
        domain=domain,
        title=f"grant obs {generate_id('n')[-6:]}",
        evidence=evidence,
    )
    await db.commit()
    return row


async def _grant_rows(db: AsyncSession, principal: str) -> list[OAuthGrantRow]:
    return list(
        (
            await db.execute(
                select(OAuthGrantRow).where(
                    OAuthGrantRow.org_id == DEFAULT_ORG_ID,
                    OAuthGrantRow.principal_id == principal,
                )
            )
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------- #
# Ingest-side writer
# --------------------------------------------------------------------------- #


async def test_identity_finding_with_grant_writes_row(db_session: AsyncSession):
    principal = f"w1_{generate_id('n')[-8:]}@example.com"
    finding = await _record_identity_finding(
        db_session, _grant_evidence(principal=principal, app="app_slack")
    )

    rows = await _grant_rows(db_session, principal)
    assert len(rows) == 1
    row = rows[0]
    assert row.app_id == "app_slack"
    assert row.provider == "okta"
    assert row.scopes == ["openid"]
    assert row.consent_type == "user"
    assert row.source_finding_id == finding.id
    assert row.revoked_at is None


async def test_non_grant_and_non_identity_findings_write_nothing(db_session: AsyncSession):
    principal = f"w2_{generate_id('n')[-8:]}@example.com"
    # Identity finding without an app_id (token replay shape).
    await _record_identity_finding(db_session, {"principal_id": principal})
    # Grant-shaped evidence but a different domain.
    await _record_identity_finding(
        db_session,
        _grant_evidence(principal=principal, app="app_zoom"),
        domain="sigma",
    )
    assert await _grant_rows(db_session, principal) == []


async def test_reobservation_refreshes_instead_of_duplicating(db_session: AsyncSession):
    principal = f"w3_{generate_id('n')[-8:]}@example.com"
    await _record_identity_finding(
        db_session, _grant_evidence(principal=principal, app="app_slack", scopes=["openid"])
    )
    second = await _record_identity_finding(
        db_session,
        _grant_evidence(
            principal=principal,
            app="app_slack",
            scopes=["openid", "Mail.Read"],
            last_used=_NOW,
        ),
    )

    rows = await _grant_rows(db_session, principal)
    assert len(rows) == 1
    row = rows[0]
    await db_session.refresh(row)
    assert sorted(row.scopes) == sorted(["openid", "Mail.Read"])
    assert row.last_used is not None
    assert row.source_finding_id == second.id


async def test_revocation_propagates(db_session: AsyncSession):
    principal = f"w4_{generate_id('n')[-8:]}@example.com"
    await _record_identity_finding(
        db_session, _grant_evidence(principal=principal, app="app_legacy")
    )
    await _record_identity_finding(
        db_session,
        _grant_evidence(principal=principal, app="app_legacy", revoked_at=_NOW),
    )
    (row,) = await _grant_rows(db_session, principal)
    await db_session.refresh(row)
    assert row.revoked_at is not None


async def test_malformed_evidence_never_breaks_ingest(db_session: AsyncSession):
    # Grant tuple present but timestamps are garbage — the finding must still
    # be recorded (fail-open) whether or not a grant row materialises.
    principal = f"w5_{generate_id('n')[-8:]}@example.com"
    finding = await _record_identity_finding(
        db_session,
        {
            "principal_id": principal,
            "app_id": "app_x",
            "granted_at": {"not": "a date"},
            "scopes": "not-a-list",
        },
    )
    assert finding.id  # ingest survived


# --------------------------------------------------------------------------- #
# Endpoint: table-backed with derive fallback
# --------------------------------------------------------------------------- #


async def test_grants_endpoint_serves_table_with_filters(
    client, analyst_token, db_session: AsyncSession
):
    principal = f"e1_{generate_id('n')[-8:]}@example.com"
    await _record_identity_finding(
        db_session, _grant_evidence(principal=principal, app="app_a", provider="okta")
    )
    await _record_identity_finding(
        db_session,
        _grant_evidence(principal=principal, app="app_b", provider="entra", revoked_at=_NOW),
    )

    resp = await client.get(
        f"/api/v1/identity/grants?principal_id={principal}",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["total"] == 2

    active = await client.get(
        f"/api/v1/identity/grants?principal_id={principal}&active=true",
        headers=auth_header(analyst_token),
    )
    assert active.json()["total"] == 1
    assert active.json()["items"][0]["app_id"] == "app_a"

    entra = await client.get(
        f"/api/v1/identity/grants?principal_id={principal}&provider=entra",
        headers=auth_header(analyst_token),
    )
    assert entra.json()["total"] == 1
    assert entra.json()["items"][0]["provider"] == "entra"


async def test_grants_endpoint_falls_back_to_derive_when_table_empty(
    client, analyst_token, db_session: AsyncSession
):
    # Simulate pre-writer data: an identity finding inserted directly (not via
    # record_finding) so no oauth_grants row exists — with the whole table
    # empty the endpoint must derive from findings as before.
    from sqlalchemy import delete

    await db_session.execute(delete(OAuthGrantRow))
    await db_session.commit()

    principal = f"e2_{generate_id('n')[-8:]}@example.com"
    db_session.add(
        HuntFindingRow(
            id=generate_id("hfnd"),
            org_id=DEFAULT_ORG_ID,
            source="identity",
            domain="identity",
            title="legacy finding",
            description="",
            severity="medium",
            confidence=0.7,
            state="new",
            technique_ids=[],
            entities=[],
            observables=[],
            evidence=_grant_evidence(principal=principal, app="app_legacy_derive"),
            signature="",
            created_at=_NOW,
        )
    )
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/identity/grants?principal_id={principal}",
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["app_id"] == "app_legacy_derive"
