"""Tests for detection-proposal persistence + review lifecycle (#113 back half, slice 1).

End-to-end over the HTTP layer:
- POST /cti/propose-detections now upserts proposals into the org-scoped
  store and reports the counts in ``response.persisted``
- re-proposing the same bundle updates still-``proposed`` rows instead of
  duplicating; rows an analyst has decided keep their decision
- GET /cti/proposals lists + filters; accept / reject record the decision
  (one-shot — 409 once decided), 404 masks unknown / cross-org rows
"""

from __future__ import annotations

from typing import Any

from conftest import auth_header
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_cti import DetectionProposalRow

_TLP_GREEN_REF = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"


def _indicator(uid: str, *, name: str, pattern: str, ttp: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uid}",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": name,
        "description": f"{name} (test)",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-01-01T00:00:00.000Z",
        "confidence": 85,
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": ttp}],
        "object_marking_refs": [_TLP_GREEN_REF],
    }


def _bundle(tag: str) -> dict[str, Any]:
    """A 2-indicator bundle with per-test-unique STIX ids.

    Committed rows persist across tests in this conftest, so every test uses
    its own indicator ids (via ``tag``, 4 hex chars) to stay independent —
    same discipline as the grants suite's per-module org ids.
    """
    return {
        "type": "bundle",
        "id": f"bundle--aaaabbbb-cccc-dddd-eeee-00000000{tag}0",
        "objects": [
            _indicator(
                f"{tag}aaaaaa-1111-1111-1111-111111111111",
                name=f"Malicious C2 IP {tag}",
                pattern=f"[ipv4-addr:value = '198.51.{int(tag, 16) % 250}.77']",
                ttp="T1071.001",
            ),
            _indicator(
                f"{tag}bbbbbb-2222-2222-2222-222222222222",
                name=f"Phishing Domain {tag}",
                pattern=f"[domain-name:value = 'verify-{tag}.example.net']",
                ttp="T1566.002",
            ),
        ],
    }


async def _propose(client, token: str, bundle: dict[str, Any]) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle": bundle, "active_tlp": "green"},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _bundle_stix_ids(bundle: dict[str, Any]) -> list[str]:
    return [o["id"] for o in bundle["objects"]]


async def _rows_for(db: AsyncSession, bundle: dict[str, Any]) -> list[DetectionProposalRow]:
    return list(
        (
            await db.execute(
                select(DetectionProposalRow).where(
                    DetectionProposalRow.org_id == DEFAULT_ORG_ID,
                    DetectionProposalRow.source_stix_id.in_(_bundle_stix_ids(bundle)),
                )
            )
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------- #
# Persist on propose + upsert on re-propose
# --------------------------------------------------------------------------- #


async def test_propose_persists_and_reports_counts(client, analyst_token, db_session: AsyncSession):
    bundle = _bundle("00a1")
    body = await _propose(client, analyst_token, bundle)
    assert len(body["proposals"]) == 2
    assert body["persisted"] == {"created": 2, "updated": 0, "unchanged": 0}

    rows = await _rows_for(db_session, bundle)
    assert len(rows) == 2
    sample = rows[0]
    assert sample.org_id == DEFAULT_ORG_ID
    assert sample.state == "proposed"
    assert sample.bundle_id == bundle["id"]
    assert sample.sigma_yaml.strip()


async def test_repropose_upserts_instead_of_duplicating(
    client, analyst_token, db_session: AsyncSession
):
    bundle = _bundle("00a2")
    await _propose(client, analyst_token, bundle)
    body = await _propose(client, analyst_token, bundle)
    assert body["persisted"] == {"created": 0, "updated": 2, "unchanged": 0}
    assert len(await _rows_for(db_session, bundle)) == 2


async def test_decided_rows_survive_repropose(client, analyst_token, db_session: AsyncSession):
    bundle = _bundle("00a3")
    await _propose(client, analyst_token, bundle)
    row_id = (await _rows_for(db_session, bundle))[0].id
    accept = await client.post(
        f"/api/v1/cti/proposals/{row_id}/accept",
        json={"rationale": "good coverage"},
        headers=auth_header(analyst_token),
    )
    assert accept.status_code == 200, accept.text

    body = await _propose(client, analyst_token, bundle)
    assert body["persisted"] == {"created": 0, "updated": 1, "unchanged": 1}

    row = (
        await db_session.execute(
            select(DetectionProposalRow).where(DetectionProposalRow.id == row_id)
        )
    ).scalar_one()
    await db_session.refresh(row)
    assert row.state == "accepted"
    assert row.review_rationale == "good coverage"


# --------------------------------------------------------------------------- #
# List + filter
# --------------------------------------------------------------------------- #


async def test_list_proposals_and_state_filter(client, analyst_token, db_session: AsyncSession):
    bundle = _bundle("00a4")
    await _propose(client, analyst_token, bundle)
    ids = {r.id for r in await _rows_for(db_session, bundle)}

    resp = await client.get(
        "/api/v1/cti/proposals?page_size=200", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200
    listed = {i["id"] for i in resp.json()["items"]}
    assert ids <= listed

    row_id = sorted(ids)[0]
    await client.post(
        f"/api/v1/cti/proposals/{row_id}/reject",
        json={"rationale": "too noisy"},
        headers=auth_header(analyst_token),
    )

    rejected = await client.get(
        "/api/v1/cti/proposals?state=rejected&page_size=200",
        headers=auth_header(analyst_token),
    )
    rejected_ids = {i["id"] for i in rejected.json()["items"]}
    assert row_id in rejected_ids
    proposed = await client.get(
        "/api/v1/cti/proposals?state=proposed&page_size=200",
        headers=auth_header(analyst_token),
    )
    proposed_ids = {i["id"] for i in proposed.json()["items"]}
    assert (ids - {row_id}) <= proposed_ids
    assert row_id not in proposed_ids


async def test_list_requires_auth(client):
    resp = await client.get("/api/v1/cti/proposals")
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Review lifecycle guards
# --------------------------------------------------------------------------- #


async def test_decide_is_one_shot(client, analyst_token, db_session: AsyncSession):
    bundle = _bundle("00a5")
    await _propose(client, analyst_token, bundle)
    row_id = (await _rows_for(db_session, bundle))[0].id
    first = await client.post(
        f"/api/v1/cti/proposals/{row_id}/accept",
        json={},
        headers=auth_header(analyst_token),
    )
    assert first.status_code == 200
    assert first.json()["reviewed_by"] is not None
    second = await client.post(
        f"/api/v1/cti/proposals/{row_id}/reject",
        json={},
        headers=auth_header(analyst_token),
    )
    assert second.status_code == 409


async def test_unknown_proposal_is_404(client, analyst_token):
    resp = await client.post(
        "/api/v1/cti/proposals/dprop_does_not_exist/accept",
        json={},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


async def test_cross_org_proposal_masked_404(client, analyst_token, db_session: AsyncSession):
    from datetime import UTC, datetime

    from btagent_shared.utils.ids import generate_id

    from btagent_backend.db.models import OrganizationRow

    other_org = "org_ctiprop_other"
    if await db_session.get(OrganizationRow, other_org) is None:
        db_session.add(OrganizationRow(id=other_org, name="CTI-Prop Other Tenant"))
        await db_session.flush()
    now = datetime.now(UTC)
    row = DetectionProposalRow(
        id=generate_id("dprop"),
        org_id=other_org,
        proposal_id="dp_x",
        source_stix_id="indicator--cccccccc-3333-3333-3333-333333333333",
        title="Other tenant rule",
        sigma_yaml="title: x",
        technique_ids=[],
        confidence=0.5,
        state="proposed",
        created_at=now,
        updated_at=now,
    )
    db_session.add(row)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/cti/proposals/{row.id}/accept",
        json={},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404
    listing = await client.get("/api/v1/cti/proposals", headers=auth_header(analyst_token))
    assert all(i["id"] != row.id for i in listing.json()["items"])
