"""Combined hunt-run service — fan out over every findings vertical.

The three findings verticals — email (#273–#279), deception (#280–#284), and
NDR (#285–#289) — each expose their own ``run_<vertical>_hunt_and_ingest``
service, ``POST /hunt/<vertical>/run`` route, header button, and cron. This
service is the consolidation: one call that runs all three end-to-end against
the same session and returns a normalized per-vertical breakdown plus the
aggregate rollup, so an analyst can sweep every proactive source with a single
action instead of triggering each vertical separately.

Each vertical's gather is already failure-tolerant (a connector outage is
caught in ``run_<vertical>_hunt_over_connector`` and degrades to zero findings),
so running them in sequence never lets one down connector sink the batch. Like
the per-vertical services, persistence flows through
:func:`hunt_triage_service.persist_hunt_findings`, which never commits — the
caller (the API route or a future combined cron) owns the single commit.

Mock-first: every vertical's connectors default to mock mode, so this is safe
to run in CI and returns the deterministic fixture-driven findings.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import (
    deception_hunt_run_service,
    email_hunt_run_service,
    ndr_hunt_run_service,
)

logger = logging.getLogger("btagent.services.all_hunts_run")

# The verticals this sweep fans out over, in inbox-display order. Kept explicit
# (rather than discovered) so adding a vertical is a deliberate one-line edit
# that the coverage test below pins.
VERTICALS = ("email", "deception", "ndr")


async def run_all_hunts_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    lookback_hours: int = 24,
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    """Run every findings-vertical hunt in sequence and land their findings.

    Runs the email hunt over an explicit ``[start, end]`` window if both are
    given, else over ``[now - lookback_hours, now]`` (email is the only vertical
    with a time window), plus the windowless deception and NDR hunts, all
    against ``db``. Returns a summary with a normalized ``verticals`` map (each
    carries ``findings_emitted`` / ``findings_created`` / ``counts_by_severity``)
    and the aggregate ``total_findings_emitted`` / ``total_findings_created`` /
    ``counts_by_severity`` rollup. Does not commit — the caller owns that.
    """
    if not (start and end):
        now = datetime.now(UTC)
        start = (now - timedelta(hours=lookback_hours)).isoformat()
        end = now.isoformat()

    email_summary = await email_hunt_run_service.run_email_hunt_and_ingest(
        db, org_id=org_id, start=start, end=end
    )
    deception_summary = await deception_hunt_run_service.run_deception_hunt_and_ingest(
        db, org_id=org_id
    )
    ndr_summary = await ndr_hunt_run_service.run_ndr_hunt_and_ingest(db, org_id=org_id)

    raw = {
        "email": email_summary,
        "deception": deception_summary,
        "ndr": ndr_summary,
    }

    verticals: dict[str, dict[str, Any]] = {}
    total_emitted = 0
    total_created = 0
    severity_rollup: Counter[str] = Counter()
    for name in VERTICALS:
        summary = raw[name]
        emitted = int(summary["findings_emitted"])
        created = int(summary["findings_created"])
        counts = {str(k): int(v) for k, v in summary["counts_by_severity"].items()}
        verticals[name] = {
            "findings_emitted": emitted,
            "findings_created": created,
            "counts_by_severity": counts,
        }
        total_emitted += emitted
        total_created += created
        severity_rollup.update(counts)

    result = {
        "org_id": org_id,
        "verticals": verticals,
        "total_findings_emitted": total_emitted,
        "total_findings_created": total_created,
        "counts_by_severity": dict(severity_rollup),
    }
    logger.info(
        "all_hunts_and_ingest org=%s: emitted=%d created=%d",
        org_id,
        total_emitted,
        total_created,
    )
    return result
