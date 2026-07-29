"""Tests for the draft → analyst-final edit-pair export (#113).

Covers the pure edit-distance maths, the org-scoped service export, and the
read-only HTTP route:

* Levenshtein / normalised distance / line-level counts behave.
* An edited proposal yields a DPO-style pair (``chosen`` = analyst body,
  ``rejected`` = drafted body) with a non-zero distance; an unedited one is
  excluded by default and included (distance 0) on request.
* The export never crosses an org boundary, and the route gates on ``hunt:view``.

Isolation: every DB test seeds a dedicated per-test org (``generate_id('org')``),
never ``DEFAULT_ORG_ID`` — the backend suite shares one session-scoped in-memory
SQLite where committed rows persist, so COUNT assertions must be scoped.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest_asyncio
from btagent_shared.types.detection_proposal import ProposalState, PROutcome
from btagent_shared.utils.ids import generate_id
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.services import detection_edit_export_service as export_svc

_DRAFT = (
    "title: Mimikatz execution\n"
    "logsource:\n  category: process_creation\n"
    "detection:\n  sel:\n    Image|endswith: \\mimikatz.exe\n  condition: sel\n"
    "level: medium\n"
)
_FINAL = (
    "title: Mimikatz execution (tuned)\n"
    "logsource:\n  category: process_creation\n"
    "detection:\n  sel:\n    Image|endswith: \\mimikatz.exe\n"
    "  filter:\n    User|startswith: SVC_\n  condition: sel and not filter\n"
    "level: high\n"
)


@pytest_asyncio.fixture()
async def dedicated_org(db_session: AsyncSession) -> str:
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name=f"ee-{org_id}", created_at=datetime.now(UTC)))
    await db_session.commit()
    return org_id


async def _seed(
    db: AsyncSession,
    org_id: str,
    *,
    final: str | None = None,
    state: str = ProposalState.PROPOSED.value,
    pr_url: str | None = None,
) -> DetectionProposalRow:
    now = datetime.now(UTC)
    row = DetectionProposalRow(
        id=generate_id("dprop"),
        org_id=org_id,
        proposal_id=f"dp_{generate_id('n')}",
        source_stix_id=f"indicator--{generate_id('n')}",
        title="Mimikatz execution",
        sigma_yaml=_DRAFT,
        final_sigma_yaml=final,
        technique_ids=["T1003.001"],
        confidence=0.7,
        state=state,
        pr_outcome=PROutcome.PR_OPENED.value if pr_url else PROutcome.PROPOSED.value,
        pr_url=pr_url,
        reviewed_by="usr_engineer" if final else None,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    await db.flush()
    return row


# --------------------------------------------------------------------------- #
# Pure edit-distance maths
# --------------------------------------------------------------------------- #


class TestEditDistance:
    def test_levenshtein_basics(self) -> None:
        assert export_svc.levenshtein("", "") == 0
        assert export_svc.levenshtein("abc", "abc") == 0
        assert export_svc.levenshtein("", "abc") == 3
        assert export_svc.levenshtein("kitten", "sitting") == 3
        assert export_svc.levenshtein("flaw", "lawn") == 2
        # Symmetric.
        assert export_svc.levenshtein("sitting", "kitten") == 3

    def test_identical_rule_has_zero_distance(self) -> None:
        m = export_svc.compute_edit_metrics(_DRAFT, _DRAFT)
        assert m.char_distance == 0
        assert m.normalized_distance == 0.0
        assert m.similarity == 1.0
        assert (m.lines_added, m.lines_removed, m.lines_changed) == (0, 0, 0)

    def test_edited_rule_has_bounded_positive_distance(self) -> None:
        m = export_svc.compute_edit_metrics(_DRAFT, _FINAL)
        assert m.char_distance > 0
        assert 0.0 < m.normalized_distance <= 1.0
        assert m.similarity == round(1.0 - m.normalized_distance, 6)
        assert m.draft_chars == len(_DRAFT)
        assert m.final_chars == len(_FINAL)
        # The tuned rule adds a filter line and rewrites the condition/level.
        assert m.lines_added + m.lines_changed > 0

    def test_empty_draft_is_all_insertion(self) -> None:
        m = export_svc.compute_edit_metrics("", _FINAL)
        assert m.char_distance == len(_FINAL)
        assert m.normalized_distance == 1.0
        assert m.similarity == 0.0

    def test_oversized_bodies_are_truncated_not_refused(self) -> None:
        big = "a" * (export_svc.MAX_DISTANCE_CHARS + 500)
        m = export_svc.compute_edit_metrics(big, big + "zzz")
        assert m.truncated is True
        assert m.draft_chars == len(big)


# --------------------------------------------------------------------------- #
# Service export
# --------------------------------------------------------------------------- #


class TestExportEditPairs:
    async def test_edited_row_yields_a_preference_pair(self, db_session, dedicated_org) -> None:
        row = await _seed(
            db_session, dedicated_org, final=_FINAL, state=ProposalState.MODIFIED.value
        )
        pairs, summary = await export_svc.export_edit_pairs(db_session, org_id=dedicated_org)

        assert len(pairs) == 1
        pair = pairs[0]
        assert pair.proposal_row_id == row.id
        assert pair.edited is True
        assert pair.draft_sigma_yaml == _DRAFT
        assert pair.final_sigma_yaml == _FINAL
        assert pair.metrics.char_distance > 0

        payload = pair.to_dict()
        # DPO framing: analyst body is chosen, the drafted body rejected.
        assert payload["chosen"] == _FINAL
        assert payload["rejected"] == _DRAFT

        assert summary.total_pairs == 1
        assert summary.edited_pairs == 1
        assert summary.edited_fraction == 1.0
        assert summary.mean_normalized_distance > 0
        assert summary.techniques_covered == ["T1003.001"]

    async def test_unedited_rows_excluded_by_default_included_on_request(
        self, db_session, dedicated_org
    ) -> None:
        await _seed(db_session, dedicated_org)  # never edited
        await _seed(db_session, dedicated_org, final=_FINAL, state=ProposalState.MODIFIED.value)

        edited_only, summary = await export_svc.export_edit_pairs(db_session, org_id=dedicated_org)
        assert len(edited_only) == 1
        assert summary.unedited_pairs == 0

        everything, all_summary = await export_svc.export_edit_pairs(
            db_session, org_id=dedicated_org, include_unedited=True
        )
        assert len(everything) == 2
        assert all_summary.total_pairs == 2
        assert all_summary.edited_pairs == 1
        assert all_summary.unedited_pairs == 1
        assert all_summary.edited_fraction == 0.5
        unedited = next(p for p in everything if not p.edited)
        # An unedited draft is a distance-0 positive: chosen == rejected.
        assert unedited.metrics.char_distance == 0
        assert unedited.final_sigma_yaml == unedited.draft_sigma_yaml

    async def test_final_identical_to_draft_is_not_an_edit(self, db_session, dedicated_org) -> None:
        await _seed(db_session, dedicated_org, final=_DRAFT, state=ProposalState.MODIFIED.value)
        pairs, summary = await export_svc.export_edit_pairs(db_session, org_id=dedicated_org)
        assert pairs == []
        assert summary.total_pairs == 0
        assert summary.mean_normalized_distance == 0.0

    async def test_only_shipped_filter(self, db_session, dedicated_org) -> None:
        await _seed(db_session, dedicated_org, final=_FINAL, state=ProposalState.MODIFIED.value)
        shipped = await _seed(
            db_session,
            dedicated_org,
            final=_FINAL,
            state=ProposalState.MODIFIED.value,
            pr_url="https://git.example.test/detections/pull/7",
        )
        pairs, _ = await export_svc.export_edit_pairs(
            db_session, org_id=dedicated_org, only_shipped=True
        )
        assert [p.proposal_row_id for p in pairs] == [shipped.id]

    async def test_export_is_org_scoped(self, db_session, dedicated_org) -> None:
        other_org = generate_id("org")
        db_session.add(
            OrganizationRow(id=other_org, name=f"ee-{other_org}", created_at=datetime.now(UTC))
        )
        await db_session.flush()
        await _seed(db_session, dedicated_org, final=_FINAL, state=ProposalState.MODIFIED.value)
        await _seed(db_session, other_org, final=_FINAL, state=ProposalState.MODIFIED.value)

        mine, mine_summary = await export_svc.export_edit_pairs(db_session, org_id=dedicated_org)
        theirs, _ = await export_svc.export_edit_pairs(db_session, org_id=other_org)
        assert mine_summary.total_pairs == 1
        assert {p.org_id for p in mine} == {dedicated_org}
        assert {p.org_id for p in theirs} == {other_org}
        assert not ({p.proposal_row_id for p in mine} & {p.proposal_row_id for p in theirs})

    async def test_limit_is_clamped(self, db_session, dedicated_org) -> None:
        for _ in range(3):
            await _seed(db_session, dedicated_org, final=_FINAL, state=ProposalState.MODIFIED.value)
        pairs, _ = await export_svc.export_edit_pairs(db_session, org_id=dedicated_org, limit=2)
        assert len(pairs) == 2
        # An absurd limit clamps instead of raising.
        pairs, _ = await export_svc.export_edit_pairs(
            db_session, org_id=dedicated_org, limit=10_000_000
        )
        assert len(pairs) == 3

    async def test_empty_export_has_zeroed_summary(self, db_session, dedicated_org) -> None:
        pairs, summary = await export_svc.export_edit_pairs(db_session, org_id=dedicated_org)
        assert pairs == []
        assert summary.total_pairs == 0
        assert summary.edited_fraction == 0.0
        assert summary.median_normalized_distance == 0.0
        assert summary.techniques_covered == []


# --------------------------------------------------------------------------- #
# HTTP route (read-only, RBAC-gated)
# --------------------------------------------------------------------------- #


class TestEditPairExportEndpoint:
    async def test_export_endpoint_returns_pairs_and_summary(
        self, client, analyst_token, db_session
    ) -> None:
        from conftest import auth_header

        from btagent_backend.db.models import DEFAULT_ORG_ID

        row = await _seed(
            db_session, DEFAULT_ORG_ID, final=_FINAL, state=ProposalState.MODIFIED.value
        )
        await db_session.commit()

        resp = await client.get(
            "/api/v1/cti/proposals/edit-pairs", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] >= 1
        mine = [i for i in body["items"] if i["proposal_row_id"] == row.id]
        assert len(mine) == 1
        item = mine[0]
        assert item["chosen"] == _FINAL
        assert item["rejected"] == _DRAFT
        assert item["edited"] is True
        assert item["metrics"]["char_distance"] > 0
        assert 0.0 < item["metrics"]["normalized_distance"] <= 1.0
        assert body["summary"]["total_pairs"] == body["total"]

    async def test_export_endpoint_requires_auth(self, client) -> None:
        resp = await client.get("/api/v1/cti/proposals/edit-pairs")
        assert resp.status_code in (401, 403)

    async def test_export_route_is_not_shadowed_by_row_id_paths(
        self, client, analyst_token
    ) -> None:
        """``/proposals/edit-pairs`` resolves to the export, not a row id."""
        from conftest import auth_header

        resp = await client.get(
            "/api/v1/cti/proposals/edit-pairs?limit=1", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 200, resp.text
        assert "summary" in resp.json()
