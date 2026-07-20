"""Tests for the combined all-hunts sweep service + API (``POST /hunt/all/run``).

Covers the consolidation that fans out over every findings vertical (email,
deception, NDR) in one call:

* the service runs all three end-to-end over their (mock-first) connectors and
  lands findings from every domain, returning a per-vertical breakdown whose
  emitted/created counts sum to the aggregate rollup;
* the aggregate ``counts_by_severity`` equals the sum of the per-vertical ones;
* the API route lands findings from all three domains, is RBAC-gated.
"""

from conftest import auth_header
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services import all_hunts_run_service as svc

# Wide window so every email connector's mid-2026 fixtures fall inside it (the
# email vertical is windowed; a rolling lookback would miss the fixed fixtures).
_WIDE = {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T00:00:00Z"}


async def _domains(db_session) -> set[str]:
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow.domain).where(HuntFindingRow.org_id == DEFAULT_ORG_ID)
            )
        )
        .scalars()
        .all()
    )
    return set(rows)


# --- service ---


async def test_run_all_lands_every_vertical(db_session):
    summary = await svc.run_all_hunts_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, start=_WIDE["start"], end=_WIDE["end"]
    )

    # Every declared vertical is present in the breakdown.
    assert set(summary["verticals"]) == set(svc.VERTICALS)

    # Per-vertical counts sum to the aggregate rollup.
    per_emitted = sum(v["findings_emitted"] for v in summary["verticals"].values())
    per_created = sum(v["findings_created"] for v in summary["verticals"].values())
    assert summary["total_findings_emitted"] == per_emitted
    assert summary["total_findings_created"] == per_created

    # The severity rollup is the element-wise sum of the per-vertical ones.
    assert sum(summary["counts_by_severity"].values()) == summary["total_findings_emitted"]

    # Findings from all three domains landed in the inbox.
    assert {"email", "deception", "ndr"} <= await _domains(db_session)


async def test_run_all_created_matches_persisted_rows(db_session):
    summary = await svc.run_all_hunts_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, start=_WIDE["start"], end=_WIDE["end"]
    )
    # Scope the count to the sweep's own domains: other findings-verticals
    # (e.g. the agentic hunt) can leak committed rows into the shared org from
    # earlier test files, and the sweep never touches those domains.
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.org_id == DEFAULT_ORG_ID,
                    HuntFindingRow.domain.in_(("email", "deception", "ndr")),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == summary["total_findings_created"]


# --- API ---


async def test_run_all_hunts_route_lands_findings(client, analyst_token):
    resp = await client.post("/api/v1/hunt/all/run", json=_WIDE, headers=auth_header(analyst_token))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert set(data["verticals"]) == set(svc.VERTICALS)
    assert data["total_findings_created"] >= 1
    per_created = sum(v["findings_created"] for v in data["verticals"].values())
    assert data["total_findings_created"] == per_created

    for domain in ("email", "deception", "ndr"):
        inbox = await client.get(
            f"/api/v1/hunt/findings?domain={domain}", headers=auth_header(analyst_token)
        )
        assert inbox.status_code == 200, inbox.text
        assert inbox.json()["clusters"], f"no {domain} clusters"


async def test_run_all_default_lookback_runs_cleanly(client, analyst_token):
    # No body → default 24h email lookback. The sweep must still succeed and
    # return a well-formed rollup; the windowless deception + NDR verticals land
    # even if no recent mail matches the fixed email fixtures.
    resp = await client.post("/api/v1/hunt/all/run", headers=auth_header(analyst_token))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert set(data) == {
        "verticals",
        "total_findings_emitted",
        "total_findings_created",
        "counts_by_severity",
    }
    assert data["total_findings_created"] >= 1


async def test_run_all_requires_auth(client):
    resp = await client.post("/api/v1/hunt/all/run", json=_WIDE)
    assert resp.status_code in (401, 403)
