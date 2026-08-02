"""B7 / P4.1: the investigation row must be committed before the agent starts.

``POST /investigations`` used to flush (not commit) the new row and defer the
commit to response middleware, then start the agent. The background task — and
``start_investigation``'s *synchronous* failure path — write status through
their OWN session, so their UPDATE matched zero rows: a build failure's FAILED
status was always lost and the case sat "pending" with no error.

The regression pin is the ORDERING: by the time ``start_investigation`` is
invoked, the request session has committed. (FAILED-status survival follows —
a committed row is visible to the agent session's UPDATE. A live cross-session
read can't be asserted here: the suite's in-memory SQLite gives every *new*
pooled connection an empty database, so concurrent-session visibility is a
connection-pool artifact rather than a commit-semantics signal.)
"""

from __future__ import annotations

from helpers import auth_header
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow


async def test_row_committed_before_agent_start(
    client: AsyncClient, analyst_token: str, db_session, monkeypatch
):
    commits: list[int] = []
    original_commit = AsyncSession.commit

    async def _counting_commit(self):
        await original_commit(self)
        commits.append(1)

    monkeypatch.setattr(AsyncSession, "commit", _counting_commit)

    tm = client._transport.app.state.task_manager
    observed: dict[str, int] = {}

    async def _record_commit_state(investigation_id: str, config: dict) -> None:
        observed["commits_at_start"] = len(commits)

    tm.start_investigation.side_effect = _record_commit_state
    try:
        resp = await client.post(
            "/api/v1/investigations",
            headers=auth_header(analyst_token),
            json={
                "title": "B7 commit-ordering probe",
                "description": "",
                "severity": "low",
            },
        )
    finally:
        tm.start_investigation.side_effect = None

    assert resp.status_code in (200, 201), resp.text
    inv_id = resp.json()["id"]

    # The load-bearing assertion: at the moment the agent was started, the
    # request session had already committed at least once (the route's
    # explicit pre-start commit) — not zero times as in the flush-only bug.
    assert observed["commits_at_start"] >= 1

    # And the row genuinely persisted.
    row = (
        await db_session.execute(select(InvestigationRow).where(InvestigationRow.id == inv_id))
    ).scalar_one()
    assert row.status == "pending"
