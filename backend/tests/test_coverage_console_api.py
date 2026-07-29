"""API tests for the Coverage Console route (#501).

``GET /api/v1/coverage/console`` is the read-only, RBAC-gated (``hunt:view``)
composition of the detection-engineering loop. These tests pin the route
contract rather than the aggregation maths (covered in
``test_coverage_console.py``):

* unauthenticated callers are refused;
* a real validation run shows up in the console the same way it shows up in the
  coverage map (the console must not diverge from its own sources);
* the payload's sections are all present even for a brand-new org;
* org B's caller never sees org A's coverage through the route.

Isolation: the cross-tenant test provisions two dedicated orgs with
``generate_id("org")`` and issues each a token, because the backend suite shares
one session-scoped in-memory SQLite database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from btagent_shared.utils.ids import generate_id

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import OrganizationRow, UserRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.db.models_validation import DetectionValidationRunRow
from tests.helpers import auth_header

_PASSWORD = "Console-P@ss-501!"


async def _org_with_analyst(db_session) -> tuple[str, str]:
    """Create a fresh org + an analyst in it; return ``(org_id, token)``."""
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name=f"console-{org_id}"))
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"console_{org_id}",
        email=f"{org_id}@btagent.test",
        password_hash=hash_password(_PASSWORD),
        role="analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    token = create_token_pair(user.id, user.username, user.role, org_id=org_id).access_token
    return org_id, token


async def _seed_coverage(db_session, org_id: str) -> None:
    """A validated technique, a silent gap, and a draft awaiting review."""
    db_session.add(
        DetectionValidationRunRow(
            id=generate_id("dvr"),
            org_id=org_id,
            run_id=generate_id("valrun"),
            packs=[],
            scenarios_run=1,
            total_techniques=2,
            detected_pct=50.0,
            gaps=["T1003"],
            coverage_by_technique=[{"technique_id": "T1059"}, {"technique_id": "T1003"}],
            emulated=True,
            target_env="sandbox",
            verdicts=[
                {"technique_id": "T1059", "verdict": "validated"},
                {"technique_id": "T1003", "verdict": "silent_gap"},
            ],
            generated_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    db_session.add(
        DetectionProposalRow(
            id=generate_id("dprop"),
            org_id=org_id,
            proposal_id=f"p-{generate_id('x')}",
            source_stix_id=f"src-{generate_id('s')}",
            title="Detect T1078",
            sigma_yaml="title: seed\n",
            technique_ids=["T1078"],
            confidence=0.5,
            state="proposed",
        )
    )
    await db_session.commit()


async def test_coverage_console_requires_auth(client):
    resp = await client.get("/api/v1/coverage/console")
    assert resp.status_code in (401, 403)


async def test_coverage_console_returns_every_section(client, analyst_token):
    resp = await client.get("/api/v1/coverage/console", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # A brand-new org still gets the full shape — a missing key would break the
    # console's panels rather than render an empty state.
    for key in (
        "generated_at",
        "stale_days",
        "summary",
        "tactics",
        "techniques",
        "broken_rules",
        "telemetry_gaps",
        "verdict_counts",
        "next_best_actions",
    ):
        assert key in body, key
    assert body["stale_days"] == 90
    assert body["verdict_counts"]["total"] >= 0


async def test_coverage_console_reflects_a_real_validation_run(client, analyst_token):
    # The console must agree with the surface it composes: a technique the
    # coverage map calls fresh cannot read as stale here.
    created = await client.post("/api/v1/validation/runs", headers=auth_header(analyst_token))
    assert created.status_code == 201, created.text

    resp = await client.get("/api/v1/coverage/console", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_id = {t["technique_id"]: t for t in body["techniques"]}
    assert "T1059.001" in by_id
    assert by_id["T1059.001"]["status"] == "fresh"
    assert by_id["T1059.001"]["stale"] is False

    map_resp = await client.get(
        "/api/v1/validation/coverage-map", headers=auth_header(analyst_token)
    )
    map_by_id = {e["technique_id"]: e for e in map_resp.json()["items"]}
    assert map_by_id["T1059.001"]["stale"] == by_id["T1059.001"]["stale"]


async def test_coverage_console_honours_stale_days(client, analyst_token):
    resp = await client.get(
        "/api/v1/coverage/console",
        params={"stale_days": 1},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["stale_days"] == 1
    # Out-of-range values are refused rather than silently clamped.
    bad = await client.get(
        "/api/v1/coverage/console",
        params={"stale_days": 0},
        headers=auth_header(analyst_token),
    )
    assert bad.status_code == 422


async def test_coverage_console_never_leaks_across_orgs(client, db_session):
    org_a, token_a = await _org_with_analyst(db_session)
    _org_b, token_b = await _org_with_analyst(db_session)
    await _seed_coverage(db_session, org_a)

    resp_a = await client.get("/api/v1/coverage/console", headers=auth_header(token_a))
    assert resp_a.status_code == 200, resp_a.text
    body_a = resp_a.json()
    assert {t["technique_id"] for t in body_a["techniques"]} == {"T1059", "T1003", "T1078"}
    assert body_a["verdict_counts"]["total"] == 2
    assert body_a["summary"]["proposals_awaiting_review"] == 1

    # Org B seeded nothing. Exact counts are safe here because both orgs are
    # per-test and no other test writes into them.
    resp_b = await client.get("/api/v1/coverage/console", headers=auth_header(token_b))
    assert resp_b.status_code == 200, resp_b.text
    body_b = resp_b.json()
    assert body_b["techniques"] == []
    assert body_b["broken_rules"] == []
    assert body_b["telemetry_gaps"] == []
    assert body_b["next_best_actions"] == []
    assert body_b["verdict_counts"]["total"] == 0
    assert body_b["summary"]["total_techniques"] == 0
    assert body_b["summary"]["open_proposals"] == 0
