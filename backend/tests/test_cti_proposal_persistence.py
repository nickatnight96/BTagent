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


# --------------------------------------------------------------------------- #
# Historical telemetry validation (#113 slice 2)
# --------------------------------------------------------------------------- #


async def test_validate_stores_verdict_on_row(
    client, analyst_token, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    bundle = _bundle("00b1")
    await _propose(client, analyst_token, bundle)
    row_id = (await _rows_for(db_session, bundle))[0].id

    resp = await client.post(
        f"/api/v1/cti/proposals/{row_id}/validate",
        json={"backends": ["splunk", "crowdstrike"], "lookback_hours": 720},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    validation = body["validation"]
    assert validation is not None
    assert validation["verdict"] in {"matched", "clean", "error"}
    assert {b["backend"] for b in validation["backends"]} == {"splunk", "crowdstrike"}
    assert body["validated_at"] is not None
    # Review lifecycle untouched.
    assert body["state"] == "proposed"

    # Surfaces in the listing too.
    listing = await client.get(
        "/api/v1/cti/proposals?page_size=200", headers=auth_header(analyst_token)
    )
    row = next(i for i in listing.json()["items"] if i["id"] == row_id)
    assert row["validation"]["verdict"] == validation["verdict"]


async def test_validate_unknown_row_is_404(client, analyst_token, monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    resp = await client.post(
        "/api/v1/cti/proposals/dprop_missing/validate",
        json={},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404


async def test_validate_untranspilable_rule_reads_error(
    client, analyst_token, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    bundle = _bundle("00b2")
    await _propose(client, analyst_token, bundle)
    row = (await _rows_for(db_session, bundle))[0]
    row.sigma_yaml = "just: a\nplain: mapping\n"
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/cti/proposals/{row.id}/validate",
        json={"backends": ["splunk"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    validation = resp.json()["validation"]
    assert validation["verdict"] == "error"
    assert "transpile failed" in validation["backends"][0]["error"]


# --------------------------------------------------------------------------- #
# Detection-repo PR composer (#113 slice 3)
# --------------------------------------------------------------------------- #

import pytest_asyncio  # noqa: E402
from btagent_shared.utils.ids import generate_id as _gen_id  # noqa: E402

from btagent_backend.auth.jwt import create_token_pair, hash_password  # noqa: E402
from btagent_backend.db.models import UserRow  # noqa: E402


@pytest_asyncio.fixture
async def senior_token(db_session: AsyncSession) -> str:
    from datetime import UTC, datetime

    user = UserRow(
        id=_gen_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"cti_senior_{_gen_id('n')}",
        email=f"cti_senior_{_gen_id('e')}@btagent.test",
        password_hash=hash_password("Str0ng!Passw0rd"),
        role="senior_analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return create_token_pair(user.id, user.username, user.role).access_token


async def _accept_all(client, token: str, db, bundle) -> list[str]:
    ids = sorted(r.id for r in await _rows_for(db, bundle))
    for rid in ids:
        resp = await client.post(
            f"/api/v1/cti/proposals/{rid}/accept", json={}, headers=auth_header(token)
        )
        assert resp.status_code == 200, resp.text
    return ids


async def test_compose_pr_ships_accepted_rules(
    client, analyst_token, senior_token, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    from btagent_agents.mcp.servers.git_mcp import MOCK_PR_LEDGER

    MOCK_PR_LEDGER.clear()

    bundle = _bundle("00c1")
    await _propose(client, analyst_token, bundle)
    ids = await _accept_all(client, analyst_token, db_session, bundle)

    resp = await client.post(
        "/api/v1/cti/proposals/compose-pr",
        json={"row_ids": ids},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rule_count"] == 2
    assert body["is_mock"] is True
    assert body["pr_url"].startswith("https://")
    assert len(MOCK_PR_LEDGER) == 1
    paths = MOCK_PR_LEDGER[0]["files"]
    assert all(f["path"].startswith("rules/t1") for f in paths)

    # PR back-link stamped and surfaced in the listing.
    listing = await client.get(
        "/api/v1/cti/proposals?page_size=200", headers=auth_header(analyst_token)
    )
    stamped = [i for i in listing.json()["items"] if i["id"] in ids]
    assert all(i["pr_url"] == body["pr_url"] for i in stamped)


async def test_compose_pr_refuses_unaccepted_rows(
    client, analyst_token, senior_token, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    bundle = _bundle("00c2")
    await _propose(client, analyst_token, bundle)
    ids = sorted(r.id for r in await _rows_for(db_session, bundle))

    resp = await client.post(
        "/api/v1/cti/proposals/compose-pr",
        json={"row_ids": ids},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 409
    assert "not accepted" in resp.json()["detail"]


async def test_compose_pr_refuses_already_shipped(
    client, analyst_token, senior_token, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    bundle = _bundle("00c3")
    await _propose(client, analyst_token, bundle)
    ids = await _accept_all(client, analyst_token, db_session, bundle)

    first = await client.post(
        "/api/v1/cti/proposals/compose-pr",
        json={"row_ids": ids},
        headers=auth_header(senior_token),
    )
    assert first.status_code == 200
    second = await client.post(
        "/api/v1/cti/proposals/compose-pr",
        json={"row_ids": ids},
        headers=auth_header(senior_token),
    )
    assert second.status_code == 409
    assert "already shipped" in second.json()["detail"]


async def test_compose_pr_requires_senior(client, analyst_token, monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    resp = await client.post(
        "/api/v1/cti/proposals/compose-pr",
        json={"row_ids": ["dprop_x"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403


async def test_compose_pr_unknown_row_is_404(client, senior_token, monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    resp = await client.post(
        "/api/v1/cti/proposals/compose-pr",
        json={"row_ids": ["dprop_missing"]},
        headers=auth_header(senior_token),
    )
    assert resp.status_code == 404
